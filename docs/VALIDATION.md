# Preview validation

The local Windows Clang 23.1.3 build passes four CTest targets. The native suite performs 1,427 assertions and 53,760 exhaustive reduced-lattice packet comparisons across generated IPv4 and IPv6 policies, with an independent ordered-rule evaluator. IPv6 cases cross 32/64-bit word boundaries. The suite also checks subtraction disjointness/conservation, full-domain cardinalities, first-match union coverage, policy equivalence despite different partitions, every generated comparison witness, strict parsing, markup escaping, and budget errors.

The separate standard-library Python CLI suite performs at least 79 assertions, verifies example witnesses using `ipaddress` and an independent evaluator, checks arbitrary-precision counts using Python integers, exercises error/gate statuses and truncation, verifies source/installed documentation links, and proves existing report files/hardlinks are preserved. Symbolic-link checks run when the OS permits creation. Python is not used by the core tool.

CI adds Linux GCC, Windows MSVC, macOS Clang, and a Linux Clang AddressSanitizer/UndefinedBehaviorSanitizer job. Release packaging depends on that workflow and repeats native tests plus installed-layout version/example checks on each target. Inspect the current commit's Actions result; configuration alone is not evidence that CI passed.

Finite generated cases are regression evidence, not a mechanically verified theorem. No production-scale performance benchmark, hostile-input fuzzing campaign, vendor firewall conformance suite, or live-network validation is claimed. A complete symbolic result applies only to the schema and semantics in DESIGN.md. This preview cannot establish real network reachability or make up for an incomplete policy model.
