# Contributing

Build and run CTest before proposing a change. For interval or policy semantics, add a regression with a concrete counterexample and extend the independent evaluator/property cases as appropriate. Preserve full-domain coverage, disjointness, first-owner provenance, exact counts, explicit incomplete status, and new-file-only output.

The policy schema is intentionally narrow. New match dimensions or vendor importers must document their semantics and unsupported cases; do not silently map unknown constructs to allow/deny or call an incomplete translation equivalent. Keep examples synthetic and keep private policies, recordings, credentials, build products, and runtime state out of commits.

Compiler warnings are errors. Linux sanitizer CI and native Windows/macOS checks must pass. The included C++ API is internal and currently has no source/ABI compatibility guarantee. CLI/report schema changes need documented migration or a new version.
