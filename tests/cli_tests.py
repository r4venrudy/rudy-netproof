"""Standard-library process/format contracts, independent cardinalities and witness replay."""
import ipaddress
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
checks = 0

def check(condition, label):
    global checks
    checks += 1
    assert condition, label

def run(*args, code=0):
    result = subprocess.run([str(binary), *map(str, args)], text=True, encoding="utf-8", capture_output=True, timeout=20)
    check(result.returncode == code, (args, result.returncode, result.stderr))
    return result

local_links = [target.split("#")[0] for target in re.findall(r"\]\(([^)]+)\)", (root / "README.md").read_text(encoding="utf-8")) if "://" not in target and not target.startswith("#")]
check(all((root / target).is_file() for target in local_links) and (root / "assets/banner.svg").is_file(), "source and installed documentation links/assets resolve")

base = root / "examples/baseline.json"
candidate = root / "examples/candidate.json"
original = json.loads(base.read_text())
updated = json.loads(candidate.read_text())
analysis = json.loads(run("analyze", base, "--format", "json").stdout)
check(analysis["complete"] and analysis["summary"]["fullyShadowed"] == 1, "shadowed rule summary")
check(next(r for r in analysis["rules"] if r["id"] == "stale-tls-v4")["blockers"][0]["rule"] == "tls-prod-v4", "first owner provenance")
run("analyze", base, "--rows", "1", "--fail-on", "shadowed", code=1)
comparison = json.loads(run("compare", base, candidate, "--format", "json", "--fail-on", "opened", code=1).stdout)
expected_opened = 2**48 + 2**128 * (65536 - 1024)
expected_closed = 128 * 256 * (65536 - 1024)
check(int(comparison["summary"]["openedTuples"]) == expected_opened, "independent IPv4 and IPv6 newly allowed cardinalities")
check(int(comparison["summary"]["closedTuples"]) == expected_closed, "independent newly denied cardinality")

def independent_decision(policy, packet):
    for rule in policy["rules"]:
        if rule["protocol"] not in ("any", packet["protocol"]):
            continue
        hit = True
        for field in ("source", "destination"):
            if rule[field] != "any":
                network = ipaddress.ip_network(rule[field], strict=True)
                addr = ipaddress.ip_address(packet[field])
                hit = hit and addr.version == network.version and addr in network
        hit = hit and rule["sourcePorts"][0] <= packet["sourcePort"] <= rule["sourcePorts"][1]
        hit = hit and rule["destinationPorts"][0] <= packet["destinationPort"] <= rule["destinationPorts"][1]
        if hit:
            return rule["action"], rule["id"]
    return policy["default"], "$default"

for change in comparison["changes"]:
    packet = change["witness"]
    before = independent_decision(original, packet)
    after = independent_decision(updated, packet)
    check(before[0] != after[0] and (after[0] == "allow") == (change["change"] == "opened"), "independent witness counterexample")
    check((before[1], after[1]) == (change["beforeRule"], change["afterRule"]), "independent witness decisive rule IDs")
    trace = json.loads(run("explain", candidate, "--source", packet["source"], "--destination", packet["destination"], "--source-port", packet["sourcePort"], "--destination-port", packet["destinationPort"], "--protocol", packet["protocol"], "--format", "json").stdout)
    check((trace["action"], trace["decisiveRule"]) == after, "concrete replay agrees with independent evaluator")
    src = change["sourceRange"]
    dst = change["destinationRange"]
    sp = change["sourcePorts"]
    dp = change["destinationPorts"]
    cardinality = (int(ipaddress.ip_address(src[1])) - int(ipaddress.ip_address(src[0])) + 1) * (int(ipaddress.ip_address(dst[1])) - int(ipaddress.ip_address(dst[0])) + 1) * (sp[1] - sp[0] + 1) * (dp[1] - dp[0] + 1)
    check(cardinality == int(change["tuples"]), "independent region cardinality")

same = json.loads(run("compare", base, base, "--format", "json", "--fail-on", "changed").stdout)
check(same["equivalent"] and not same["changes"], "identical inputs pass changed gate")
limited = json.loads(run("compare", base, candidate, "--format", "json", "--rows", "1", "--fail-on", "opened", code=1).stdout)
check(limited["summary"] == comparison["summary"] and limited["omittedChanges"] > 0, "display limit preserves exact summary and gates")
run("analyze", base, "--max-operations", "1", code=2)
run("analyze", base, "--max-fragments", "1", code=2)
run("compare", base, candidate, "--format", "dot", code=2)
run("analyze", base, "--fail-on", "opened", code=2)
run("analyze", base, "--rows", "0", code=2)
run("analyze", base, "--rows", "1", "--rows", "2", code=2)
run("explain", base, code=2)
run("analyze", base, "--protocol", "udp", code=2)
run("analyze", base, "--max-operations", "50000001", code=2)
run("unknown", base, code=2)

with tempfile.TemporaryDirectory(prefix="netproof-test-") as directory:
    temp = Path(directory)
    output = temp / "report.json"
    run("analyze", base, "--format", "json", "--output", output)
    saved = output.read_bytes()
    check(json.loads(saved)["schema"] == "rudy-netproof/report-v1", "new report file")
    run("analyze", candidate, "--output", output, code=2)
    check(output.read_bytes() == saved, "existing output preserved")
    link = temp / "hardlink.json"
    link.hardlink_to(output)
    run("analyze", candidate, "--output", link, code=2)
    check(output.read_bytes() == saved, "hard-linked output preserved")
    try:
        symlink = temp / "symlink.json"
        symlink.symlink_to(output)
    except OSError:
        pass  # Windows symbolic links require developer mode or an elevated token.
    else:
        run("analyze", candidate, "--output", symlink, code=2)
        check(output.read_bytes() == saved, "symbolic-link output preserved")
    missing = temp / "incomplete.json"
    failed = run("compare", base, candidate, "--max-operations", "1", "--output", missing, code=2)
    check(not missing.exists() and failed.stdout == "", "budget failure creates no partial proof")
    invalid = temp / "bad.json"
    for content in ('{"x":1,"x":2}', "[]", '{"schema":', base.read_text().replace('"sourcePorts": [', '"sourcePortsTypo": [')):
        invalid.write_text(content)
        run("analyze", invalid, code=2)
    payload = dict(original, name="<img src=x onerror=alert(1)> & policy")
    invalid.write_text(json.dumps(payload))
    html = run("analyze", invalid, "--format", "html").stdout
    check("<img src=x" not in html and "&lt;img src=x" in html, "policy text is inert HTML")
    check("<script" not in html and "default-src 'none'" in html and "<details>" in html, "offline no-script interactive report")

print(f"CLI contract assertions passed: {checks}; exact cardinalities and all example witnesses checked independently.")
