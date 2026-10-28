#pragma once
#include <array>
#include <compare>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace netproof {
using Json = nlohmann::json;
inline constexpr const char* version = "0.1.1-preview";
struct Error : std::runtime_error { using std::runtime_error::runtime_error; };
struct Key {
  std::array<std::uint32_t, 4> word{};
  auto operator<=>(const Key&) const = default;
  static Key small(std::uint32_t n) { return {{{0, 0, 0, n}}}; }
};
Key increment(Key); Key decrement(Key); Key difference(Key, const Key&);
struct Count {
  std::vector<std::uint32_t> digit{0};
  explicit Count(std::uint32_t n = 0);
  static Count from(const Key&);
  Count& operator+=(const Count&);
  friend Count operator*(const Count&, const Count&);
  std::string str() const;
  bool zero() const { return digit.size() == 1 && digit[0] == 0; }
  bool operator==(const Count&) const = default;
};
struct Range { Key lo{}, hi{}; auto operator<=>(const Range&) const = default; };
struct Network { int family{}; Range range; };
Network network(const std::string&); // Strict canonical network prefix; "any" is handled by policy expansion.
Key address(const std::string&, int family);
std::string address_text(const Key&, int family);
struct Box {
  int family{4}; int protocol{6};
  std::array<Range, 4> axis{}; // Source address, destination address, source port, destination port.
  auto operator<=>(const Box&) const = default;
};
std::optional<Box> intersection(const Box&, const Box&);
std::vector<Box> subtract(const Box&, const Box& contained);
Count volume(const Box&);
struct Rule { std::string id; bool allow{}; std::vector<Box> match; };
struct Policy { std::string name, family; bool default_allow{}; std::vector<Rule> rules; };
Policy parse_policy(const std::string&);
Policy read_policy(const std::filesystem::path&);
std::vector<Box> universe(const std::string& family);
struct Budget {
  std::uint64_t max_operations{5'000'000}, max_fragments{200'000}, operations{}, fragments{};
  void step(); void generated(std::uint64_t);
};
struct Cell { Box box; bool allow{}; std::string rule; };
struct Blocker { std::string rule; bool allow{}; Count tuples; Box witness; };
struct RuleResult {
  std::string id, status; bool allow{}; Count matched, reachable;
  std::optional<Box> witness; std::vector<Blocker> blockers;
};
struct Analysis { std::vector<Cell> cells; std::vector<RuleResult> rules; Count allowed, denied; };
Analysis analyze(const Policy&, Budget&);
struct Change { Box box; std::string before_rule, after_rule; bool opened{}; };
struct Comparison { Analysis before, after; std::vector<Change> changes; Count opened, closed; };
Comparison compare(const Policy&, const Policy&, Budget&);
struct Packet { int family{4}, protocol{6}; std::array<Key, 4> value{}; };
bool contains(const Box&, const Packet&);
Json witness(const Box&);
Json explain(const Policy&, const Packet&);
Json report(const Policy&, const Analysis&, const Budget&, std::size_t rows = 100);
Json report(const Policy&, const Policy&, const Comparison&, const Budget&, std::size_t rows = 100);
std::string html(const Json&);
std::string text(const Json&);
std::string dot(const Analysis&);
void write_new(const std::optional<std::filesystem::path>&, const std::string&);
} // namespace netproof
