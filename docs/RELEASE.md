Rudy NetProof is a C++20 offline first-match network-policy reasoning engine.

The patch preview publishes packages through a dedicated directory so the release attaches exactly the three tested native archives and their checksum manifest.

- IPv4/IPv6 symbolic decision regions for source/destination addresses and TCP/UDP ports.
- Exact first-match reachability, union shadowing, blocking-owner evidence, and concrete tuple explanations.
- Semantic policy comparison with newly allowed/denied regions, arbitrary-precision counts, replayable witnesses, and CI gates.
- JSON, text, expandable offline HTML, and DOT shadowing graphs.
- Bounded parsing/computation, new-file-only reports, synthetic policies, independent oracle checks, and native cross-platform CI.

Verify SHA256SUMS.txt before extracting. Packages include `bin/`, synthetic `examples/`, docs, and licenses; no runtime installation is required. Use `bin/netproof --help` (`bin\netproof.exe` on Windows).

Developer preview. Results are exact within the normalized stateless TCP/UDP model. There is no live probing or vendor-config import; NAT, routing, state, ICMP, and other omitted semantics remain outside scope.
