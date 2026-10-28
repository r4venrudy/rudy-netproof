#include "netproof.hpp"
#include <algorithm>
#include <charconv>
#include <iostream>
#include <map>

using namespace netproof;
static const char* help = R"HELP(Rudy NetProof — offline first-match TCP/UDP decision-space analysis
netproof analyze POLICY [--format text|json|html|dot] [--fail-on shadowed]
netproof compare BEFORE AFTER [--format text|json|html] [--fail-on opened|changed]
netproof explain POLICY --source IP --destination IP --source-port N --destination-port N --protocol tcp|udp

Options: --output NEW_FILE --rows 1..500 --max-operations 1..50000000 --max-fragments 1..500000
All analysis is offline. "any" protocol means TCP and UDP only. No live firewall is inspected.
Exit 0: complete, requested gate not reached; 1: complete, requested gate reached; 2: invalid/incomplete/error.
)HELP";
static std::uint64_t numeric(const std::string& s, std::uint64_t maximum, bool allow_zero = false) {
  std::uint64_t n{}; const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), n);
  if (s.empty() || ec != std::errc{} || end != s.data() + s.size() || n > maximum || (!allow_zero && n == 0)) throw Error("Numeric option is outside its documented range");
  return n;
}
int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "--version") { std::cout << "netproof " << version << '\n'; return 0; }
    if (argc == 1 || (argc == 2 && std::string(argv[1]) == "--help")) { std::cout << help; return argc == 1 ? 2 : 0; }
    const std::string command = argv[1];
    if (command != "analyze" && command != "compare" && command != "explain") throw Error("Unknown command; use --help");
    std::vector<std::string> positional; std::map<std::string, std::string> option;
    const std::vector<std::string> allowed = {"--format", "--output", "--rows", "--max-operations", "--max-fragments", "--fail-on", "--source", "--destination", "--source-port", "--destination-port", "--protocol"};
    for (int i = 2; i < argc; ++i) {
      const std::string key = argv[i];
      if (!key.starts_with("--")) { positional.push_back(key); continue; }
      if (std::find(allowed.begin(), allowed.end(), key) == allowed.end() || i + 1 == argc || std::string(argv[i + 1]).starts_with("--")) throw Error("Unknown option or missing option value");
      if (!option.emplace(key, argv[++i]).second) throw Error("Repeated option");
    }
    if (positional.size() != (command == "compare" ? 2U : 1U)) throw Error("Wrong number of policy files; use --help");
    const auto get = [&option](const std::string& key, const std::string& fallback) { const auto it = option.find(key); return it == option.end() ? fallback : it->second; };
    const auto format = get("--format", "text"), gate = get("--fail-on", "none");
    if (format != "text" && format != "json" && format != "html" && !(format == "dot" && command == "analyze")) throw Error("Unsupported output format for this command");
    if ((command == "analyze" && gate != "none" && gate != "shadowed") || (command == "compare" && gate != "none" && gate != "opened" && gate != "changed") || (command == "explain" && gate != "none")) throw Error("Unsupported failure gate for this command");
    Budget budget;
    budget.max_operations = numeric(get("--max-operations", "5000000"), 50'000'000);
    budget.max_fragments = numeric(get("--max-fragments", "200000"), 500'000);
    const auto rows = static_cast<std::size_t>(numeric(get("--rows", "100"), 500));
    const auto p = read_policy(positional[0]); Json result; std::string rendered; bool failed = false;
    const std::array<std::string, 5> packet_options = {"--source", "--destination", "--source-port", "--destination-port", "--protocol"};
    if (command != "explain") for (const auto& key : packet_options) if (option.contains(key)) throw Error("Packet options require the explain command");
    if (command == "analyze") {
      const auto a = analyze(p, budget); result = report(p, a, budget, rows);
      failed = gate == "shadowed" && std::any_of(a.rules.begin(), a.rules.end(), [](const RuleResult& r) { return r.status == "fully-shadowed"; });
      if (format == "dot") rendered = dot(a);
    } else if (command == "compare") {
      const auto other = read_policy(positional[1]); const auto comparison = compare(p, other, budget);
      result = report(p, other, comparison, budget, rows);
      failed = (gate == "opened" && !comparison.opened.zero()) || (gate == "changed" && !comparison.changes.empty());
    } else {
      for (const auto& key : packet_options) if (!option.contains(key)) throw Error("Explain requires all five packet options");
      Packet packet; packet.family = option.at("--source").find(':') == std::string::npos ? 4 : 6;
      const auto protocol = option.at("--protocol"); if (protocol != "tcp" && protocol != "udp") throw Error("Concrete protocol must be tcp or udp");
      packet.protocol = protocol == "tcp" ? 6 : 17;
      packet.value = {address(option.at("--source"), packet.family), address(option.at("--destination"), packet.family),
        Key::small(static_cast<std::uint32_t>(numeric(option.at("--source-port"), 65535, true))), Key::small(static_cast<std::uint32_t>(numeric(option.at("--destination-port"), 65535, true)))};
      result = explain(p, packet);
    }
    if (format == "json") rendered = result.dump(2) + '\n';
    else if (format == "html") rendered = html(result);
    else if (format == "text") rendered = text(result);
    std::optional<std::filesystem::path> output;
    if (option.contains("--output")) output = option.at("--output");
    write_new(output, rendered); return failed ? 1 : 0;
  } catch (const std::exception& e) { std::cerr << "netproof: " << e.what() << '\n'; return 2; }
}
