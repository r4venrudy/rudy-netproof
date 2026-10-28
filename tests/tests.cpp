#include "netproof.hpp"
#include <algorithm>
#include <functional>
#include <iostream>
#include <random>

using namespace netproof;
static int checks = 0;
static void check(bool pass, const std::string& message) { ++checks; if (!pass) throw Error("Test failed: " + message); }
static void rejects(const std::function<void()>& f, const std::string& message) {
  bool rejected = false; try { f(); } catch (const std::exception&) { rejected = true; } check(rejected, message);
}
static Json rule_json(std::string id = "test", std::string action = "allow") {
  return {{"id", id}, {"action", action}, {"protocol", "tcp"}, {"source", "192.0.2.0/24"}, {"destination", "198.51.100.0/24"}, {"sourcePorts", {0, 65535}}, {"destinationPorts", {443, 443}}};
}
static Json policy_json() { return {{"schema", "rudy-netproof/policy-v1"}, {"name", "test"}, {"family", "ipv4"}, {"default", "deny"}, {"rules", Json::array()}}; }
static Policy policy(const Json& rules) { auto j = policy_json(); j["rules"] = rules; return parse_policy(j.dump()); }
static void addresses() {
  for (const auto& s : {"0.0.0.0", "255.255.255.255", "192.0.2.17"}) check(address_text(address(s, 4), 4) == s, "IPv4 round trip");
  for (const auto& s : {"::", "::1", "2001:db8::abcd", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1:2:3:4:5:6:7:8", "::ffff:abcd:1234"}) check(address(address_text(address(s, 6), 6), 6) == address(s, 6), "IPv6 round trip");
  for (const auto& s : {"1.2.3", "256.0.0.1", "01.2.3.4", "-1.2.3.4", "1.2.3.4 ", "1..2.3", "1.2.3.4.5"}) rejects([&] { (void)address(s, 4); }, "strict IPv4 syntax");
  for (const auto& s : {"1:2:3", "1::2::3", "1:2:3:4:5:6:7:8::", ":::1", "12345::", "fe80::1%eth0", "::ffff:192.0.2.1", "::+1", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9"}) rejects([&] { (void)address(s, 6); }, "strict supported IPv6 syntax");
  check(network("0.0.0.0/0").range.hi == address("255.255.255.255", 4), "IPv4 full prefix");
  check(network("::/0").range.hi == address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 6), "IPv6 full prefix");
  check(network("2001:db8::/32").range.hi == address("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 6), "IPv6 prefix boundary");
  for (const auto& s : {"192.0.2.1/24", "2001:db8::1/64", "1.2.3.4/33", "::/129", "1.2.3.4", "::/0/0", "::/-1"}) rejects([&] { (void)network(s); }, "invalid or noncanonical prefix");
  const Key maximum{{{0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU}}};
  rejects([&] { (void)increment(maximum); }, "successor overflow");
  rejects([] { (void)decrement(Key{}); }, "predecessor overflow");
  check(difference(increment(Key::small(0xffffffffU)), Key::small(1)) == Key::small(0xffffffffU), "cross-word subtraction");
  check(decrement(Key{{{1, 0, 0, 0}}}) == Key{{{0, 0xffffffffU, 0xffffffffU, 0xffffffffU}}}, "multiword borrow");
  check(volume(universe("ipv4").front()).str() == "79228162514264337593543950336", "exact 2^96 cardinality");
  check(volume(universe("ipv6").front()).str() == "497323236409786642155382248146820840100456150797347717440463976893159497012533375533056", "exact 2^288 cardinality");
  auto j = policy_json(); j["family"] = "dual"; j["default"] = "allow"; Budget budget;
  check(analyze(parse_policy(j.dump()), budget).allowed.str() == "994646472819573284310764496293641680200912301594695434881086410111347522700253838966784", "dual family counts exceed native integers");
}
static void parsing() {
  check(policy(Json::array({rule_json()})).rules.size() == 1, "valid policy");
  auto j = policy_json(); j["unknown"] = true; rejects([&] { (void)parse_policy(j.dump()); }, "unknown top-level field");
  j = policy_json(); j.erase("default"); rejects([&] { (void)parse_policy(j.dump()); }, "missing required field");
  j = policy_json(); j["schema"] = "other"; rejects([&] { (void)parse_policy(j.dump()); }, "schema version");
  j = policy_json(); j["rules"] = Json::array({rule_json(), rule_json()}); rejects([&] { (void)parse_policy(j.dump()); }, "duplicate rule IDs");
  for (const auto& name : {"id", "protocol", "source", "destination", "action"}) {
    auto r = rule_json(); r[name] = 1; rejects([&] { (void)policy(Json::array({r})); }, "field types");
  }
  for (auto port : {Json::array({-1, 2}), Json::array({1, 65536}), Json::array({1.0, 2}), Json::array({true, 2}), Json::array({4, 3}), Json::array({1})}) {
    auto r = rule_json(); r["destinationPorts"] = port; rejects([&] { (void)policy(Json::array({r})); }, "strict port interval");
  }
  auto r = rule_json(); r["protocol"] = "icmp"; rejects([&] { (void)policy(Json::array({r})); }, "unmodeled protocol refused");
  r = rule_json(); r["source"] = "::/0"; rejects([&] { (void)policy(Json::array({r})); }, "mixed family refused");
  r = rule_json(); r["id"] = "$default"; rejects([&] { (void)policy(Json::array({r})); }, "reserved rule ID refused");
  rejects([] { (void)parse_policy(R"({"schema":"a","schema":"b"})"); }, "duplicate JSON keys rejected");
  auto s = policy_json().dump(); s.insert(1, "\"rules\":[],"); rejects([&] { (void)parse_policy(s); }, "duplicate nested field rejected");
  rejects([] { (void)parse_policy(std::string(40, '[') + "0" + std::string(40, ']')); }, "deep JSON refused");
  rejects([] { (void)parse_policy(std::string(8 * 1024 * 1024 + 1, ' ')); }, "input size refused");
  j = policy_json(); for (int i = 0; i < 501; ++i) j["rules"].push_back(rule_json(std::to_string(i)));
  rejects([&] { (void)parse_policy(j.dump()); }, "rule count refused");
}
static void first_match() {
  auto a = rule_json("broad"); a["destinationPorts"] = {0, 65535};
  auto b = rule_json("blocked", "deny");
  auto c = rule_json("partial"); c["source"] = "192.0.0.0/16";
  auto p = policy(Json::array({a, b, c})); Budget budget; const auto result = analyze(p, budget);
  check(result.rules[0].status == "effective", "first rule effective");
  check(result.rules[1].status == "fully-shadowed", "deny blocked by prior allow");
  check(result.rules[2].status == "partially-shadowed", "partial reachability");
  check(result.rules[1].blockers.size() == 1 && result.rules[1].blockers[0].rule == "broad", "first blocking owner");
  for (const auto& row : result.rules) {
    auto partitioned = row.reachable; for (const auto& block : row.blockers) partitioned += block.tuples;
    check(partitioned == row.matched, "blocked plus reachable equals raw match");
  }
  Packet packet{4, 6, {address("192.0.2.1", 4), address("198.51.100.1", 4), Key::small(12345), Key::small(443)}};
  const auto e = explain(p, packet);
  check(e.at("decisiveRule") == "broad" && e.at("matchingRules").size() == 3, "all matching rules retain decisive first match");
  check(e.at("matchingRules")[0].at("decisive") == true && e.at("matchingRules")[1].at("decisive") == false, "trace first-owner flag");
  packet.protocol = 17; check(explain(p, packet).at("decisiveRule") == "$default", "TCP does not permit UDP");
  auto empty = policy(Json::array()); packet.family = 6; rejects([&] { (void)explain(empty, packet); }, "out-of-scope packet refused");
  auto dual = policy_json(); dual["family"] = "dual";
  auto dual_rule = a;
  dual_rule["source"] = "any"; dual_rule["destination"] = "any"; dual_rule["protocol"] = "any"; dual["rules"] = Json::array({dual_rule});
  Budget db; const auto da = analyze(parse_policy(dual.dump()), db);
  check(da.denied.zero() && da.rules[0].blockers.empty(), "any expands into disjoint family/protocol matches");
  Budget tiny; tiny.max_operations = 1; rejects([&] { (void)analyze(p, tiny); }, "operation failure is incomplete");
  tiny = Budget{}; tiny.max_fragments = 1; rejects([&] { (void)analyze(p, tiny); }, "fragment failure is incomplete");
  Budget cb; check(compare(p, p, cb).changes.empty(), "reflexive policy equivalence");
  auto v6 = policy_json(); v6["family"] = "ipv6"; const auto other = parse_policy(v6.dump());
  Budget mismatch; rejects([&] { (void)compare(p, other, mismatch); }, "scope mismatch refused");
  auto reordered = policy(Json::array({b, a, c})); Budget changed; const auto comparison = compare(p, reordered, changed);
  check(comparison.opened.zero() && !comparison.closed.zero(), "first-match reorder closes exactly the overridden allow region; opened=" + comparison.opened.str() + ", closed=" + comparison.closed.str());
  check(comparison.closed == result.rules[1].matched, "changed count equals exact overridden range");
  auto first_half = rule_json("first-half"), second_half = rule_json("second-half"), union_rule = rule_json("covered-by-union", "deny");
  first_half["source"] = "192.0.2.0/25"; second_half["source"] = "192.0.2.128/25";
  const auto split_policy = policy(Json::array({first_half, second_half, union_rule})); Budget union_budget;
  const auto split_analysis = analyze(split_policy, union_budget);
  check(split_analysis.rules[2].status == "fully-shadowed" && split_analysis.rules[2].blockers.size() == 2, "union of disjoint predecessors fully shadows rule");
  Budget equivalent_budget; const auto same = compare(split_policy, policy(Json::array({rule_json("renamed-broad")})), equivalent_budget);
  check(same.changes.empty(), "different rule partitions and dead-rule removal preserve decisions");
  const auto limited = report(p, reordered, comparison, changed, 0);
  check(!limited.at("equivalent").get<bool>() && limited.at("changes").empty() && limited.at("omittedChanges") == comparison.changes.size(), "row truncation never changes proof");
  auto attack = p; attack.name = "<script>alert('x')</script>&"; const auto h = html(report(attack, result, budget));
  check(h.find("<script>") == std::string::npos && h.find("&lt;script&gt;") != std::string::npos, "inert escaped HTML");
  check(h.find("default-src 'none'") != std::string::npos && h.find("https://") == std::string::npos, "self-contained restrictive HTML");
  check(dot(result).find("\"broad\" -> \"blocked\"") != std::string::npos, "shadow graph provenance");
}
struct Spec { std::array<unsigned, 4> lo{}, hi{}; int protocol{}; bool allow{}; };
static std::uint32_t draw(std::mt19937& random) { return static_cast<std::uint32_t>(random()); }
static Key materialize(unsigned n, std::size_t dimension, int family) {
  if (dimension >= 2 || family == 4) return Key::small(n);
  auto result = address("2001:db8:abcd:ffff:ffff:ffff:ffff:fffe", 6);
  for (unsigned i = 0; i < n; ++i) result = increment(result);
  return result;
}
static Policy generated(std::mt19937& random, std::vector<Spec>& specs, int family = 4) {
  Policy p{"generated", family == 4 ? "ipv4" : "ipv6", (draw(random) & 1U) != 0, {}};
  const unsigned count = 1 + draw(random) % 6;
  for (unsigned i = 0; i < count; ++i) {
    Spec s; s.protocol = (draw(random) & 1U) != 0 ? 6 : 17; s.allow = (draw(random) & 1U) != 0;
    Box box; box.protocol = s.protocol; box.family = family;
    for (std::size_t k = 0; k < 4; ++k) { s.lo[k] = draw(random) % 4; s.hi[k] = s.lo[k] + draw(random) % (4 - s.lo[k]); box.axis[k] = {materialize(s.lo[k], k, family), materialize(s.hi[k], k, family)}; }
    specs.push_back(s); p.rules.push_back({std::to_string(i), s.allow, {box}});
  }
  return p;
}
static bool oracle(const Policy& p, const std::vector<Spec>& specs, const std::array<unsigned, 4>& point, int protocol) {
  for (const auto& r : specs) {
    bool hit = r.protocol == protocol;
    for (std::size_t k = 0; k < 4; ++k) hit = hit && point[k] >= r.lo[k] && point[k] <= r.hi[k];
    if (hit) return r.allow;
  }
  return p.default_allow;
}
static void properties() {
  std::mt19937 random(0x52554459U);
  for (int trial = 0; trial < 80; ++trial) {
    Box whole; Box middle;
    for (std::size_t k = 0; k < 4; ++k) { whole.axis[k] = {Key{}, Key::small(3)}; const auto lo = draw(random) % 4; const auto hi = lo + draw(random) % (4 - lo); middle.axis[k] = {Key::small(lo), Key::small(hi)}; }
    const auto parts = subtract(whole, middle); Count sum = volume(middle); bool disjoint = true;
    for (std::size_t i = 0; i < parts.size(); ++i) { sum += volume(parts[i]); disjoint = disjoint && !intersection(parts[i], middle); for (std::size_t k = 0; k < i; ++k) disjoint = disjoint && !intersection(parts[i], parts[k]); }
    check(disjoint && sum == volume(whole), "subtraction conservation and disjointness");
  }
  for (int trial = 0; trial < 80; ++trial) {
    const auto family = trial % 2 == 0 ? 4 : 6;
    std::vector<Spec> spec; const auto p = generated(random, spec, family); Budget budget; const auto a = analyze(p, budget);
    bool correct = true; std::array<unsigned, 4> point{};
    for (unsigned flat = 0; flat < 256; ++flat) {
      auto n = flat; for (auto& x : point) { x = n % 4; n /= 4; }
      for (int protocol : {6, 17}) {
        Packet packet; packet.family = family; packet.protocol = protocol; for (std::size_t k = 0; k < 4; ++k) packet.value[k] = materialize(point[k], k, family);
        unsigned owners = 0; bool answer = false;
        for (const auto& cell : a.cells) if (contains(cell.box, packet)) { ++owners; answer = cell.allow; }
        correct = correct && owners == 1 && answer == oracle(p, spec, point, protocol);
      }
    }
    auto total = a.allowed; total += a.denied; Count expected;
    for (const auto& b : universe(p.family)) expected += volume(b);
    check(correct && total == expected, "all 512 reduced-lattice packets agree with independent ordered-rule oracle");
    bool explained = true;
    for (const auto& r : a.rules) { auto count = r.reachable; for (const auto& blocker : r.blockers) count += blocker.tuples; explained = explained && count == r.matched; }
    check(explained, "every generated rule accounts for all matched tuples");
    if (trial < 25) {
      std::vector<Spec> spec2; const auto p2 = generated(random, spec2, family); Budget cb; const auto c = compare(p, p2, cb); bool changes_correct = true;
      for (unsigned flat = 0; flat < 256; ++flat) {
        auto n = flat; for (auto& x : point) { x = n % 4; n /= 4; }
        for (int protocol : {6, 17}) {
          Packet packet; packet.family = family; packet.protocol = protocol; for (std::size_t k = 0; k < 4; ++k) packet.value[k] = materialize(point[k], k, family);
          unsigned regions = 0; bool opened = false;
          for (const auto& change : c.changes) if (contains(change.box, packet)) { ++regions; opened = change.opened; }
          const auto before = oracle(p, spec, point, protocol), after = oracle(p2, spec2, point, protocol);
          changes_correct = changes_correct && (regions == (before != after ? 1U : 0U)) && (regions == 0 || opened == after);
        }
      }
      check(changes_correct, "symbolic comparison equals exhaustive independent oracle");
      for (const auto& change : c.changes) {
        Packet packet{change.box.family, change.box.protocol, {}};
        for (std::size_t k = 0; k < 4; ++k) packet.value[k] = change.box.axis[k].lo;
        check(explain(p, packet).at("action") != explain(p2, packet).at("action"), "every reported witness replays a real model change");
      }
    }
  }
}
int main() {
  try { addresses(); parsing(); first_match(); properties(); std::cout << "Rudy NetProof: " << checks << " assertions passed; 53,760 exhaustive oracle packet comparisons, 80 subtraction cases.\n"; return 0; }
  catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
