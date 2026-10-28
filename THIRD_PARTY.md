# Dependency provenance

The sole library dependency is [JSON for Modern C++ v3.12.0](https://github.com/nlohmann/json/releases/tag/v3.12.0), by Niels Lohmann and contributors, under the MIT license.

- Vendored file: `third_party/nlohmann/json.hpp`
- Source: `https://raw.githubusercontent.com/nlohmann/json/v3.12.0/single_include/nlohmann/json.hpp`
- SHA-256: `aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63`
- Unmodified upstream license: `third_party/nlohmann/LICENSE.MIT`

The header hash was checked against the release's published digest. No network fetch occurs during configure, build, tests, or tool execution. Native release packages include the dependency license under `licenses/`. Python's standard library is used only by optional independent tests and release verification. GitHub Actions are pinned to immutable upstream commits.
