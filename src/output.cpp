#include "netproof.hpp"
#include <cstdio>
#include <iostream>
#include <sstream>

namespace netproof {
static std::string escape(const std::string& s) {
  std::string out;
  for (char c : s) switch (c) { case '&': out += "&amp;"; break; case '<': out += "&lt;"; break; case '>': out += "&gt;"; break; case '"': out += "&quot;"; break; case '\'': out += "&#39;"; break; default: out += c; }
  return out;
}
static std::string packet_text(const Json& p) {
  return p.at("protocol").get<std::string>() + " [" + p.at("source").get<std::string>() + "]:" + std::to_string(p.at("sourcePort").get<int>()) +
    " -> [" + p.at("destination").get<std::string>() + "]:" + std::to_string(p.at("destinationPort").get<int>());
}
std::string text(const Json& j) {
  std::ostringstream out; out << "RUDY NETPROOF " << version << " / " << j.at("kind").get<std::string>() << "\n";
  if (j.at("kind") == "analysis") {
    out << j.at("policy").get<std::string>() << " / " << j.at("family").get<std::string>() << "\n";
    out << "Fully shadowed: " << j.at("summary").at("fullyShadowed") << "; partially shadowed: " << j.at("summary").at("partiallyShadowed") << "\n";
    out << "Allowed tuples: " << j.at("summary").at("allowedTuples").get<std::string>() << "\n";
    for (const auto& r : j.at("rules")) out << r.at("id").get<std::string>() << "  " << r.at("status").get<std::string>() << "  " << r.at("reachableTuples").get<std::string>() << "/" << r.at("matchedTuples").get<std::string>() << " reachable\n";
    out << "Omitted rule rows: " << j.at("omittedRules") << "\n";
  } else if (j.at("kind") == "comparison") {
    out << j.at("before").get<std::string>() << " -> " << j.at("after").get<std::string>() << "\nEquivalent: " << (j.at("equivalent").get<bool>() ? "yes" : "no") << "\n";
    out << "Opened tuples: " << j.at("summary").at("openedTuples").get<std::string>() << "\nClosed tuples: " << j.at("summary").at("closedTuples").get<std::string>() << "\n";
    for (const auto& c : j.at("changes")) out << c.at("change").get<std::string>() << "  " << packet_text(c.at("witness")) << "  " << c.at("beforeRule").get<std::string>() << " -> " << c.at("afterRule").get<std::string>() << "\n";
    out << "Omitted change rows: " << j.at("omittedChanges") << "\n";
  } else out << packet_text(j.at("packet")) << "\n" << j.at("action").get<std::string>() << " / " << j.at("decisiveRule").get<std::string>() << "\n";
  out << "Exact within the declared stateless TCP/UDP model. No live firewall was inspected.\n";
  return out.str();
}
std::string html(const Json& j) {
  std::string out = R"HTML(<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Rudy NetProof / decision-space investigation</title><style>
:root{color-scheme:dark;--ink:#eaf3ff;--muted:#99abc0;--accent:#55e0b6;--line:#263549}*{box-sizing:border-box}body{margin:0;background:#080e16;color:var(--ink);font:15px/1.6 system-ui,sans-serif}main{max-width:1180px;margin:auto;padding:48px 24px}header{border-left:4px solid var(--accent);padding:12px 28px;margin-bottom:32px;background:linear-gradient(100deg,#101d29,#0a111b)}small,.eyebrow{font:12px/1.6 monospace;letter-spacing:2px;color:var(--accent)}h1{font-size:clamp(34px,6vw,64px);letter-spacing:-2px;line-height:1.1;margin:14px 0}h2{font-size:23px}p{color:var(--muted)}.cards{display:flex;gap:16px;flex-wrap:wrap;margin:28px 0}.card{flex:1;min-width:240px;border:1px solid var(--line);background:#101b28;padding:20px;border-radius:12px}.number{font-size:22px;overflow-wrap:anywhere;color:var(--ink)}details{border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin:12px 0;background:#0d1722}summary{cursor:pointer;font-weight:650;overflow-wrap:anywhere}code,pre{font-family:ui-monospace,monospace;overflow-wrap:anywhere}pre{white-space:pre-wrap;padding:12px;background:#080e16;max-height:500px;overflow:auto;color:#b3c9df}.tag{display:inline-block;font:12px monospace;padding:3px 8px;border-radius:4px;background:#173c33;color:var(--accent);margin-right:10px}.warn{background:#422d1c;color:#ffc68a}.fine{font-size:13px;color:var(--muted)}footer{border-top:1px solid var(--line);margin-top:40px;padding-top:18px;color:var(--muted)}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}td,th{text-align:left;padding:10px;border-bottom:1px solid var(--line)}th{color:var(--muted)}@media print{body{background:white;color:black}details{break-inside:avoid}pre{max-height:none}p,.fine,footer{color:#444}}</style><main><header><div class="eyebrow">RUDY SYSTEMS / NETWORK POLICY REASONING</div><h1>Rudy NetProof</h1><p>Every decision has a region. Every change has a witness.</p></header>)HTML";
  const auto kind = j.at("kind").get<std::string>();
  out += "<small>" + escape(kind) + " / COMPLETE MODEL ANALYSIS</small>";
  auto card = [&out](const std::string& label, const std::string& n) { out += "<div class=\"card\"><div class=\"fine\">" + escape(label) + "</div><div class=\"number\">" + escape(n) + "</div></div>"; };
  if (kind == "analysis") {
    out += "<h2>" + escape(j.at("policy").get<std::string>()) + "</h2><div class=\"cards\">";
    card("Fully shadowed rules", j.at("summary").at("fullyShadowed").dump()); card("Partially shadowed rules", j.at("summary").at("partiallyShadowed").dump()); card("Allowed packet tuples", j.at("summary").at("allowedTuples").get<std::string>()); out += "</div><h2>First-match reachability</h2>";
    for (const auto& r : j.at("rules")) {
      out += "<details><summary><span class=\"tag " + std::string(r.at("status") == "effective" ? "" : "warn") + "\">" + escape(r.at("status").get<std::string>()) + "</span>" + escape(r.at("id").get<std::string>()) + " / " + escape(r.at("action").get<std::string>()) + "</summary>";
      out += "<p>" + escape(r.at("reachableTuples").get<std::string>()) + " of " + escape(r.at("matchedTuples").get<std::string>()) + " matched tuples reach this rule.</p>";
      if (!r.at("reachableWitness").is_null()) out += "<p><code>Reachable: " + escape(packet_text(r.at("reachableWitness"))) + "</code></p>";
      out += "<div class=\"scroll\"><table><thead><tr><th>Earlier decisive rule</th><th>Action</th><th>Blocked tuples</th><th>Witness</th></tr></thead><tbody>";
      for (const auto& b : r.at("blockers")) out += "<tr><td>" + escape(b.at("rule").get<std::string>()) + "</td><td>" + escape(b.at("action").get<std::string>()) + "</td><td>" + escape(b.at("tuples").get<std::string>()) + "</td><td><code>" + escape(packet_text(b.at("witness"))) + "</code></td></tr>";
      out += "</tbody></table></div><p class=\"fine\">Omitted blockers: " + r.at("omittedBlockers").dump() + "</p></details>";
    }
    out += "<p class=\"fine\">Omitted rule rows: " + j.at("omittedRules").dump() + ". Summary totals cover every rule.</p>";
  } else if (kind == "comparison") {
    out += "<h2>" + escape(j.at("before").get<std::string>()) + " → " + escape(j.at("after").get<std::string>()) + "</h2><div class=\"cards\">";
    card("Newly allowed tuples", j.at("summary").at("openedTuples").get<std::string>()); card("Newly denied tuples", j.at("summary").at("closedTuples").get<std::string>()); card("Decision equivalence", j.at("equivalent").get<bool>() ? "Equivalent" : "Changed"); out += "</div><h2>Counterexample regions</h2>";
    for (const auto& c : j.at("changes")) out += "<details><summary><span class=\"tag " + std::string(c.at("change") == "opened" ? "warn" : "") + "\">" + c.at("change").get<std::string>() + "</span>" + escape(packet_text(c.at("witness"))) + "</summary><p>" + escape(c.at("beforeRule").get<std::string>()) + " → " + escape(c.at("afterRule").get<std::string>()) + " / " + escape(c.at("tuples").get<std::string>()) + " tuples</p><pre>" + escape(c.dump(2)) + "</pre></details>";
    out += "<p class=\"fine\">Omitted change rows: " + j.at("omittedChanges").dump() + ". Totals and equivalence use every region, regardless of this display limit.</p>";
  } else out += "<pre>" + escape(j.dump(2)) + "</pre>";
  out += "<details><summary>Evidence contract and computation budget</summary><pre>" + escape(j.contains("budget") ? j.at("budget").dump(2) : "Single concrete packet evaluation") + "</pre><p>Counts are exact address/port combinations, not traffic frequency, active hosts, or risk scores. Witnesses are model counterexamples, never transmitted packets.</p></details><footer>Stateless first-match TCP/UDP only. No NAT, connection tracking, routing, interfaces, ICMP, live collection or vendor configuration import. Developer preview · " + std::string(version) + " · Local report; no external assets or scripts.</footer></main></html>";
  return out;
}
void write_new(const std::optional<std::filesystem::path>& path, const std::string& content) {
  if (content.size() > 16 * 1024 * 1024) throw Error("Report exceeds 16 MiB output budget");
  if (!path) { std::cout << content; if (!std::cout) throw Error("Cannot write complete standard output"); return; }
#ifdef _WIN32
  std::FILE* f = _wfopen(path->c_str(), L"wbx");
#else
  std::FILE* f = std::fopen(path->c_str(), "wbx");
#endif
  if (!f) throw Error("Output must be a new writable file; existing files and links are refused");
  const auto wrote = std::fwrite(content.data(), 1, content.size(), f);
  const auto closed = std::fclose(f);
  if (wrote != content.size() || closed != 0) throw Error("Report write failed; the new output may be incomplete");
}
} // namespace netproof
