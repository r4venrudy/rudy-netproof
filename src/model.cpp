#include "netproof.hpp"
#include <algorithm>
#include <charconv>
#include <fstream>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>

namespace netproof {
Key increment(Key n) {
  for (std::size_t i = 4; i-- > 0;) if (++n.word[i] != 0) return n;
  throw Error("128-bit successor overflow");
}
Key decrement(Key n) {
  for (std::size_t i = 4; i-- > 0;) if (n.word[i]-- != 0) return n;
  throw Error("128-bit predecessor underflow");
}
Key difference(Key a, const Key& b) {
  if (a < b) throw Error("Negative interval width");
  std::uint64_t borrow = 0;
  for (std::size_t i = 4; i-- > 0;) {
    const auto sub = static_cast<std::uint64_t>(b.word[i]) + borrow;
    const auto value = static_cast<std::uint64_t>(a.word[i]);
    a.word[i] = static_cast<std::uint32_t>(value - sub);
    borrow = value < sub ? 1U : 0U;
  }
  return a;
}
constexpr std::uint64_t base = 1'000'000'000;
Count::Count(std::uint32_t n) : digit{static_cast<std::uint32_t>(n % base)} {
  if (n >= base) digit.push_back(static_cast<std::uint32_t>(n / base));
}
Count& Count::operator+=(const Count& b) {
  const auto size = std::max(digit.size(), b.digit.size());
  digit.resize(size, 0);
  std::uint64_t carry = 0;
  for (std::size_t i = 0; i < size; ++i) {
    const auto sum = static_cast<std::uint64_t>(digit[i]) + (i < b.digit.size() ? b.digit[i] : 0U) + carry;
    digit[i] = static_cast<std::uint32_t>(sum % base); carry = sum / base;
  }
  if (carry != 0) digit.push_back(static_cast<std::uint32_t>(carry));
  return *this;
}
Count operator*(const Count& a, const Count& b) {
  Count result; result.digit.assign(a.digit.size() + b.digit.size(), 0);
  for (std::size_t i = 0; i < a.digit.size(); ++i) {
    std::uint64_t carry = 0;
    for (std::size_t j = 0; j < b.digit.size(); ++j) {
      const auto sum = static_cast<std::uint64_t>(a.digit[i]) * b.digit[j] + result.digit[i + j] + carry;
      result.digit[i + j] = static_cast<std::uint32_t>(sum % base); carry = sum / base;
    }
    result.digit[i + b.digit.size()] = static_cast<std::uint32_t>(carry);
  }
  while (result.digit.size() > 1 && result.digit.back() == 0) result.digit.pop_back();
  return result;
}
Count Count::from(const Key& n) {
  Count result;
  for (auto word : n.word) { result = result * Count(65536) * Count(65536); result += Count(word); }
  return result;
}
std::string Count::str() const {
  std::ostringstream out; out << digit.back();
  for (std::size_t i = digit.size() - 1; i-- > 0;) out << std::setw(9) << std::setfill('0') << digit[i];
  return out.str();
}
static std::uint32_t number(const std::string& value, std::uint32_t maximum, int radix = 10) {
  std::uint32_t n{};
  auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), n, radix);
  if (value.empty() || ec != std::errc{} || end != value.data() + value.size() || n > maximum) throw Error("Invalid numeric address or prefix component");
  return n;
}
static std::vector<std::string> split(const std::string& value, char separator) {
  std::vector<std::string> result; std::size_t start = 0;
  for (;;) {
    const auto end = value.find(separator, start);
    result.push_back(value.substr(start, end == std::string::npos ? end : end - start));
    if (end == std::string::npos) return result;
    start = end + 1;
  }
}
Key address(const std::string& value, int family) {
  if (value.empty() || value.size() > 64) throw Error("Invalid address length");
  Key result;
  if (family == 4) {
    const auto part = split(value, '.');
    if (part.size() != 4) throw Error("IPv4 requires four decimal octets");
    for (const auto& octet : part) {
      if (octet.size() > 1 && octet.front() == '0') throw Error("Ambiguous leading-zero IPv4 octet");
      result.word[3] = (result.word[3] << 8) | number(octet, 255);
    }
  } else if (family == 6) {
    if (value.find_first_not_of("0123456789abcdefABCDEF:") != std::string::npos) throw Error("IPv6 requires hexadecimal groups; zone IDs and embedded dotted IPv4 are unsupported");
    const auto gap = value.find("::");
    std::vector<std::string> left, right;
    if (gap == std::string::npos) left = split(value, ':');
    else {
      if (value.find("::", gap + 2) != std::string::npos) throw Error("Repeated IPv6 compression");
      if (gap != 0) left = split(value.substr(0, gap), ':');
      if (gap + 2 != value.size()) right = split(value.substr(gap + 2), ':');
    }
    if ((gap == std::string::npos && left.size() != 8) || (gap != std::string::npos && left.size() + right.size() >= 8)) throw Error("Invalid IPv6 group count");
    std::array<std::uint32_t, 8> group{};
    auto parse = [](const std::string& s) { if (s.size() > 4) throw Error("Oversized IPv6 group"); return number(s, 65535, 16); };
    for (std::size_t i = 0; i < left.size(); ++i) group[i] = parse(left[i]);
    for (std::size_t i = 0; i < right.size(); ++i) group[8 - right.size() + i] = parse(right[i]);
    for (std::size_t i = 0; i < 4; ++i) result.word[i] = (group[i * 2] << 16) | group[i * 2 + 1];
  } else throw Error("Unknown address family");
  return result;
}
std::string address_text(const Key& n, int family) {
  std::ostringstream out;
  if (family == 4) {
    for (int shift = 24; shift >= 0; shift -= 8) { if (shift != 24) out << '.'; out << ((n.word[3] >> shift) & 255U); }
  } else {
    // Fully expanded hexadecimal groups are unambiguous and round-trip without platform APIs.
    out << std::hex;
    for (std::size_t i = 0; i < 8; ++i) { if (i) out << ':'; out << ((n.word[i / 2] >> (i % 2 == 0 ? 16 : 0)) & 65535U); }
  }
  return out.str();
}
Network network(const std::string& value) {
  const auto slash = value.find('/');
  if (slash == std::string::npos || value.find('/', slash + 1) != std::string::npos) throw Error("Expected an explicit CIDR prefix");
  const int family = value.find(':') == std::string::npos ? 4 : 6;
  const auto maximum = family == 4 ? 32U : 128U;
  const auto prefix = number(value.substr(slash + 1), maximum);
  const auto original = address(value.substr(0, slash), family);
  Key lo = original, hi = original;
  const auto effective = family == 4 ? prefix + 96 : prefix;
  for (std::uint32_t i = 0; i < 4; ++i) {
    const auto bits = effective > i * 32 ? std::min(32U, effective - i * 32) : 0U;
    const auto mask = bits == 0 ? 0U : (bits == 32 ? 0xffffffffU : 0xffffffffU << (32 - bits));
    lo.word[i] &= mask; hi.word[i] |= ~mask;
  }
  if (original != lo) throw Error("CIDR host bits must be zero; use the canonical network prefix");
  return {family, {lo, hi}};
}
std::optional<Box> intersection(const Box& a, const Box& b) {
  if (a.family != b.family || a.protocol != b.protocol) return std::nullopt;
  Box result = a;
  for (std::size_t i = 0; i < 4; ++i) {
    result.axis[i] = {std::max(a.axis[i].lo, b.axis[i].lo), std::min(a.axis[i].hi, b.axis[i].hi)};
    if (result.axis[i].lo > result.axis[i].hi) return std::nullopt;
  }
  return result;
}
std::vector<Box> subtract(const Box& a, const Box& contained) {
  if (intersection(a, contained) != contained) throw Error("Subtraction requires a contained rectangle");
  Box core = a; std::vector<Box> result;
  for (std::size_t i = 0; i < 4; ++i) {
    if (core.axis[i].lo < contained.axis[i].lo) {
      Box slice = core; slice.axis[i].hi = decrement(contained.axis[i].lo); result.push_back(slice);
      core.axis[i].lo = contained.axis[i].lo;
    }
    if (contained.axis[i].hi < core.axis[i].hi) {
      Box slice = core; slice.axis[i].lo = increment(contained.axis[i].hi); result.push_back(slice);
      core.axis[i].hi = contained.axis[i].hi;
      core.axis[i].hi = contained.axis[i].hi;
    }
  }
  return result;
}
Count volume(const Box& box) {
  Count result(1);
  for (const auto& range : box.axis) { auto width = Count::from(difference(range.hi, range.lo)); width += Count(1); result = result * width; }
  return result;
}
std::vector<Box> universe(const std::string& family) {
  if (family != "ipv4" && family != "ipv6" && family != "dual") throw Error("family must be ipv4, ipv6, or dual");
  std::vector<Box> result;
  for (int f : {4, 6}) if (family == "dual" || family == (f == 4 ? "ipv4" : "ipv6")) {
    Key maximum = f == 4 ? Key::small(0xffffffffU) : Key{{{0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU}}};
    for (int protocol : {6, 17}) result.push_back({f, protocol, {{{{}, maximum}, {{}, maximum}, {{}, Key::small(65535)}, {{}, Key::small(65535)}}}});
  }
  return result;
}
static void keys(const Json& obj, const std::set<std::string>& expected) {
  if (!obj.is_object()) throw Error("Expected a JSON object");
  std::set<std::string> actual;
  for (const auto& [key, value] : obj.items()) { (void)value; actual.insert(key); }
  if (actual != expected) throw Error("Missing or unknown policy field");
}
static std::string string_field(const Json& obj, const char* key, std::size_t maximum) {
  const auto& value = obj.at(key);
  if (!value.is_string()) throw Error(std::string(key) + " must be a string");
  const auto s = value.get<std::string>();
  if (s.empty() || s.size() > maximum || std::any_of(s.begin(), s.end(), [](unsigned char c) { return c < 32 || c == 127; })) throw Error(std::string(key) + " has invalid length or control characters");
  return s;
}
static bool action(const std::string& s) { if (s == "allow") return true; if (s == "deny") return false; throw Error("action must be allow or deny"); }
static Range ports(const Json& j) {
  if (!j.is_array() || j.size() != 2) throw Error("Port range must contain two integers");
  std::array<std::uint32_t, 2> p{};
  for (std::size_t i = 0; i < 2; ++i) {
    if (!j[i].is_number_integer() || j[i].is_boolean() || j[i] < 0 || j[i] > 65535) throw Error("Ports must be integers from 0 through 65535");
    p[i] = j[i].get<std::uint32_t>();
  }
  if (p[0] > p[1]) throw Error("Port interval is reversed");
  return {Key::small(p[0]), Key::small(p[1])};
}
Policy parse_policy(const std::string& input) {
  if (input.size() > 8 * 1024 * 1024) throw Error("Policy exceeds 8 MiB");
  std::vector<std::set<std::string>> object_keys;
  auto callback = [&object_keys](int depth, Json::parse_event_t event, Json& value) {
    if (depth > 32) throw Error("JSON nesting exceeds 32");
    if (event == Json::parse_event_t::object_start) object_keys.emplace_back();
    else if (event == Json::parse_event_t::key && !object_keys.back().insert(value.get<std::string>()).second) throw Error("Duplicate JSON object key");
    else if (event == Json::parse_event_t::object_end) object_keys.pop_back();
    return true;
  };
  const auto j = Json::parse(input, callback);
  keys(j, {"schema", "name", "family", "default", "rules"});
  if (string_field(j, "schema", 64) != "rudy-netproof/policy-v1") throw Error("Unsupported policy schema");
  Policy p{string_field(j, "name", 128), string_field(j, "family", 8), action(string_field(j, "default", 8)), {}};
  const auto domain = universe(p.family);
  if (!j.at("rules").is_array() || j.at("rules").size() > 500) throw Error("rules must be an array of at most 500 entries");
  std::set<std::string> ids;
  for (const auto& r : j.at("rules")) {
    keys(r, {"id", "action", "protocol", "source", "destination", "sourcePorts", "destinationPorts"});
    const auto id = string_field(r, "id", 64);
    if (id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != std::string::npos || !ids.insert(id).second) throw Error("Rule IDs must be unique ASCII letters, digits, dot, underscore, or hyphen");
    const auto proto = string_field(r, "protocol", 8);
    if (proto != "tcp" && proto != "udp" && proto != "any") throw Error("Only tcp, udp, or any (tcp and udp) are modeled");
    const auto src = string_field(r, "source", 80), dst = string_field(r, "destination", 80);
    std::optional<Network> sn, dn;
    if (src != "any") sn = network(src);
    if (dst != "any") dn = network(dst);
    const auto sport = ports(r.at("sourcePorts")), dport = ports(r.at("destinationPorts"));
    Rule rule{id, action(string_field(r, "action", 8)), {}};
    for (auto b : domain) {
      if ((sn && sn->family != b.family) || (dn && dn->family != b.family) || (proto == "tcp" && b.protocol != 6) || (proto == "udp" && b.protocol != 17)) continue;
      if (sn) b.axis[0] = sn->range;
      if (dn) b.axis[1] = dn->range;
      b.axis[2] = sport; b.axis[3] = dport; rule.match.push_back(b);
    }
    if (rule.match.empty()) throw Error("Rule address families conflict with each other or the policy family");
    p.rules.push_back(std::move(rule));
  }
  return p;
}
Policy read_policy(const std::filesystem::path& path) {
  if (!std::filesystem::is_regular_file(path)) throw Error("Policy input must be a regular file");
  std::ifstream in(path, std::ios::binary);
  if (!in) throw Error("Cannot open policy input");
  std::string input; std::array<char, 8192> buffer{};
  while (in.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || in.gcount() != 0) {
    input.append(buffer.data(), static_cast<std::size_t>(in.gcount()));
    if (input.size() > 8 * 1024 * 1024) throw Error("Policy exceeds 8 MiB");
  }
  if (!in.eof()) throw Error("Cannot read complete policy input");
  return parse_policy(input);
}
void Budget::step() { if (operations >= max_operations) throw Error("Operation budget exhausted; no complete proof was produced"); ++operations; }
void Budget::generated(std::uint64_t n) { if (n > max_fragments - std::min(fragments, max_fragments)) throw Error("Fragment budget exhausted; no complete proof was produced"); fragments += n; }
bool contains(const Box& box, const Packet& p) {
  if (box.family != p.family || box.protocol != p.protocol) return false;
  for (std::size_t i = 0; i < 4; ++i) if (p.value[i] < box.axis[i].lo || p.value[i] > box.axis[i].hi) return false;
  return true;
}
} // namespace netproof
