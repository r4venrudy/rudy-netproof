# Decision-space engine

The modeled domain is the Cartesian product `(family, protocol, source address, destination address, source port, destination port)`. Family is IPv4/IPv6, protocol is TCP/UDP, and every address/port coordinate is an unsigned integer. All endpoint values, including special-use addresses and port zero, participate; routability and protocol-state validity are not inferred. There are four disjoint family/protocol universes in a dual-family policy.

## Representation

An address is four big-endian 32-bit words, with lexicographic comparison. IPv4 uses the final word only. No compiler-specific 128-bit integer, host-endian cast, platform address parser, or network API is needed. Inclusive address intervals can span the full 128-bit domain. Output IPv6 uses eight hexadecimal groups without zero compression; it is intended to round-trip, not claim shortest canonical formatting. Address parsing follows the hexadecimal forms described in [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291), with the explicit subset restrictions in the README.

A rectangle contains one family/protocol pair and four inclusive coordinate intervals. Intersection takes the maximum lower and minimum upper endpoints on each axis. To subtract a contained rectangle, the algorithm successively peels the low and high slabs from each axis, restricting the remaining core to the intersection before processing the next axis. This produces at most eight mutually disjoint remainder rectangles. Endpoint successor/predecessor operations are performed only when the strict interval ordering proves they cannot overflow.

Tuple cardinality is the product of the four inclusive widths. Full IPv6 address-pair/port space needs 289 bits for its cardinality; an individual TCP or UDP universe contains `2^288` tuples. A small base-1,000,000,000 unsigned integer implementation performs exact addition/multiplication and decimal serialization. Cardinalities are JSON strings so readers never round them through a floating-point number.

## First-match partition

1. Begin with each family/protocol universe undecided.
2. Intersect each rule's disjoint family/protocol matches with the undecided rectangles.
3. Assign every intersection to that rule, then carry forward only the subtraction remainder.
4. Attribute already-decided overlapping regions to their original owners as blockers.
5. Assign the final undecided rectangles to `$default`.

Every decided tuple therefore has exactly one first owner. For each rule, `reachable tuples + sum(blocked tuples) = raw matched tuples`. This handles union shadowing: several earlier rules may collectively make a later rule unreachable even if no individual rule covers it. Raw matches of different protocols/families are disjoint, so expanding `any` does not double-count them.

`effective` means every raw matching tuple reaches the rule. `partially-shadowed` means some do. `fully-shadowed` means none do. These statuses do not establish whether removing a reachable rule preserves decisions. A reachable deny with a deny default can be redundant without being shadowed.

## Semantic comparison

Partition both policies within identical family scopes, then intersect their final decision regions. Retain only intersections whose actions differ. These intersections are disjoint, so newly allowed and newly denied cardinalities add exactly. One endpoint tuple per region is a deterministic counterexample; reports retain both decisive owners. Identical actions with different owners are equivalent under this model.

Complexity depends on fragmentation, not the number of concrete packets. Pathological overlaps can fragment space and comparisons can require a quadratic number of cell-pair tests. Box-pair operations and cumulative generated fragments have separate budgets, shared across the full comparison. Budget exhaustion throws an error; it never becomes a successful partial result. Display limits apply only after computation.

## Boundaries

This is a normalized policy model, not a firewall configuration translator, packet simulator, reachability oracle for a real network, or verification of vendor semantics. It excludes NAT, stateful rules, routing, interface/direction selectors, TCP flags, fragments, ICMP, nested chains, dynamic sets, time/identity rules, and host availability. Real-world conclusions require a faithful model plus independent validation of those omitted systems.

The CLI reads only explicitly supplied files and writes a single explicitly requested new report. It creates no sockets and executes no subprocesses. HTML uses escaped text, native disclosure elements, no scripts/external assets, and a restrictive Content Security Policy. JSON parsing rejects duplicate keys, unknown fields, malformed UTF-8, deep nesting, and unsupported schema constructs.
