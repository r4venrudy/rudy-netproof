# Synthetic policy review

These documentation-range addresses and invented rules are controlled model inputs. NetProof never contacts them.

- `baseline.json`: dual-family policy with DNS, TLS, SSH maintenance, a fully shadowed deny, and a partially shadowed broader deny.
- `candidate.json`: moves the stale TLS deny ahead of its former blocker, introduces a TCP/8443 listener for all IPv4 sources, and broadens the IPv6 TLS destination from `/64` to `/63`.

Expected changes:

| Change | Exact tuple cardinality |
| --- | --- |
| Newly allowed IPv4 debug listener | `2^32 * 65536 = 2^48` |
| Newly allowed additional IPv6 destination half | `2^64 * 2^64 * 64512` |
| Newly denied IPv4 TLS source half | `128 * 256 * 64512` |

The CLI suite independently verifies these totals and the first-match rule IDs of every displayed counterexample. A very large IPv6 tuple count says nothing about how many actual hosts exist or can be reached. Use counts to compare modeled decision regions, not to rank risks.
