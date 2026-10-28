#include "netproof.hpp"
#include <algorithm>
#include <map>

namespace netproof {
Analysis analyze(const Policy& p, Budget& budget) {
  Analysis result;
  auto pending = universe(p.family);
  budget.generated(static_cast<std::uint64_t>(pending.size()));
  for (const auto& rule : p.rules) {
    RuleResult row; row.id = rule.id; row.allow = rule.allow;
    std::map<std::string, std::size_t> blocker_index;
    for (const auto& match : rule.match) {
      row.matched += volume(match);
      // Decided cells are mutually disjoint, so each blocked tuple has exactly one first owner.
      for (const auto& cell : result.cells) {
        budget.step();
        if (auto hit = intersection(cell.box, match)) {
          const auto [it, inserted] = blocker_index.emplace(cell.rule, row.blockers.size());
          if (inserted) row.blockers.push_back({cell.rule, cell.allow, Count{}, *hit});
          row.blockers[it->second].tuples += volume(*hit);
        }
      }
      std::vector<Box> remaining;
      for (const auto& box : pending) {
        budget.step();
        if (auto hit = intersection(box, match)) {
          auto pieces = subtract(box, *hit);
          budget.generated(static_cast<std::uint64_t>(pieces.size()) + 1);
          remaining.insert(remaining.end(), pieces.begin(), pieces.end());
          row.reachable += volume(*hit);
          if (!row.witness) row.witness = *hit;
          result.cells.push_back({*hit, rule.allow, rule.id});
        } else remaining.push_back(box);
      }
      pending = std::move(remaining);
    }
    row.status = row.reachable.zero() ? "fully-shadowed" : (row.reachable == row.matched ? "effective" : "partially-shadowed");
    result.rules.push_back(std::move(row));
  }
  budget.generated(static_cast<std::uint64_t>(pending.size()));
  for (const auto& box : pending) result.cells.push_back({box, p.default_allow, "$default"});
  std::sort(result.cells.begin(), result.cells.end(), [](const Cell& a, const Cell& b) { return a.box < b.box; });
  for (const auto& cell : result.cells) (cell.allow ? result.allowed : result.denied) += volume(cell.box);
  return result;
}
Comparison compare(const Policy& before, const Policy& after, Budget& budget) {
  if (before.family != after.family) throw Error("Comparison requires identical policy family scopes");
  Comparison result; result.before = analyze(before, budget); result.after = analyze(after, budget);
  for (const auto& a : result.before.cells) for (const auto& b : result.after.cells) {
    budget.step();
    if (a.allow == b.allow) continue;
    if (auto hit = intersection(a.box, b.box)) {
      budget.generated(1);
      result.changes.push_back({*hit, a.rule, b.rule, b.allow});
      (b.allow ? result.opened : result.closed) += volume(*hit);
    }
  }
  std::sort(result.changes.begin(), result.changes.end(), [](const Change& a, const Change& b) { return a.box < b.box; });
  return result;
}
Json witness(const Box& b) {
  return {{"family", b.family == 4 ? "ipv4" : "ipv6"}, {"protocol", b.protocol == 6 ? "tcp" : "udp"},
    {"source", address_text(b.axis[0].lo, b.family)}, {"destination", address_text(b.axis[1].lo, b.family)},
    {"sourcePort", b.axis[2].lo.word[3]}, {"destinationPort", b.axis[3].lo.word[3]}};
}
Json explain(const Policy& p, const Packet& packet) {
  const auto domain = universe(p.family);
  if (std::none_of(domain.begin(), domain.end(), [&](const Box& b) { return contains(b, packet); })) throw Error("Packet is outside the modeled policy scope");
  Json matches = Json::array(); bool decision = p.default_allow; std::string owner = "$default";
  for (const auto& rule : p.rules) if (std::any_of(rule.match.begin(), rule.match.end(), [&](const Box& b) { return contains(b, packet); })) {
    if (matches.empty()) { decision = rule.allow; owner = rule.id; }
    matches.push_back({{"rule", rule.id}, {"action", rule.allow ? "allow" : "deny"}, {"decisive", matches.empty()}});
  }
  Box point{packet.family, packet.protocol, {}};
  for (std::size_t i = 0; i < 4; ++i) point.axis[i] = {packet.value[i], packet.value[i]};
  return {{"schema", "rudy-netproof/report-v1"}, {"version", version}, {"kind", "explanation"}, {"complete", true},
    {"policy", p.name}, {"packet", witness(point)}, {"action", decision ? "allow" : "deny"}, {"decisiveRule", owner}, {"matchingRules", matches}};
}
static Json region(const Box& b) {
  return {{"family", b.family == 4 ? "ipv4" : "ipv6"}, {"protocol", b.protocol == 6 ? "tcp" : "udp"},
    {"sourceRange", {address_text(b.axis[0].lo, b.family), address_text(b.axis[0].hi, b.family)}},
    {"destinationRange", {address_text(b.axis[1].lo, b.family), address_text(b.axis[1].hi, b.family)}},
    {"sourcePorts", {b.axis[2].lo.word[3], b.axis[2].hi.word[3]}}, {"destinationPorts", {b.axis[3].lo.word[3], b.axis[3].hi.word[3]}},
    {"tuples", volume(b).str()}, {"witness", witness(b)}};
}
static Json usage(const Budget& b) {
  return {{"operations", b.operations}, {"maxOperations", b.max_operations}, {"generatedFragments", b.fragments}, {"maxFragments", b.max_fragments}};
}
Json report(const Policy& p, const Analysis& a, const Budget& b, std::size_t rows) {
  Json rules = Json::array(); std::size_t shadowed = 0, partial = 0;
  for (const auto& r : a.rules) {
    shadowed += r.status == "fully-shadowed" ? 1U : 0U; partial += r.status == "partially-shadowed" ? 1U : 0U;
    if (rules.size() >= rows) continue;
    Json blockers = Json::array();
    for (const auto& block : r.blockers) {
      if (blockers.size() >= rows) break;
      blockers.push_back({{"rule", block.rule}, {"action", block.allow ? "allow" : "deny"}, {"tuples", block.tuples.str()}, {"witness", witness(block.witness)}});
    }
    Json row = {{"id", r.id}, {"action", r.allow ? "allow" : "deny"}, {"status", r.status}, {"matchedTuples", r.matched.str()},
      {"reachableTuples", r.reachable.str()}, {"blockers", blockers}, {"omittedBlockers", r.blockers.size() - blockers.size()}};
    row["reachableWitness"] = r.witness ? witness(*r.witness) : Json(nullptr); rules.push_back(std::move(row));
  }
  return {{"schema", "rudy-netproof/report-v1"}, {"version", version}, {"kind", "analysis"}, {"complete", true}, {"policy", p.name}, {"family", p.family},
    {"summary", {{"ruleCount", a.rules.size()}, {"fullyShadowed", shadowed}, {"partiallyShadowed", partial}, {"decisionRegions", a.cells.size()},
      {"allowedTuples", a.allowed.str()}, {"deniedTuples", a.denied.str()}}}, {"rules", rules}, {"omittedRules", a.rules.size() - rules.size()}, {"budget", usage(b)}};
}
Json report(const Policy& before, const Policy& after, const Comparison& c, const Budget& b, std::size_t rows) {
  Json changes = Json::array();
  for (const auto& change : c.changes) {
    if (changes.size() >= rows) break;
    auto row = region(change.box); row["change"] = change.opened ? "opened" : "closed";
    row["beforeRule"] = change.before_rule; row["afterRule"] = change.after_rule; changes.push_back(std::move(row));
  }
  return {{"schema", "rudy-netproof/report-v1"}, {"version", version}, {"kind", "comparison"}, {"complete", true},
    {"before", before.name}, {"after", after.name}, {"family", before.family}, {"equivalent", c.changes.empty()},
    {"summary", {{"openedTuples", c.opened.str()}, {"closedTuples", c.closed.str()}, {"changedRegions", c.changes.size()}}},
    {"changes", changes}, {"omittedChanges", c.changes.size() - changes.size()}, {"budget", usage(b)}};
}
std::string dot(const Analysis& a) {
  std::string out = "digraph shadowing {\n  rankdir=LR;\n  node [shape=box];\n";
  for (const auto& r : a.rules) {
    out += "  " + Json(r.id).dump() + " [label=" + Json(r.id + "\n" + r.status).dump() + "];\n";
    for (const auto& b : r.blockers) out += "  " + Json(b.rule).dump() + " -> " + Json(r.id).dump() + " [label=" + Json(b.tuples.str() + " tuples").dump() + "];\n";
  }
  return out + "}\n";
}
} // namespace netproof
