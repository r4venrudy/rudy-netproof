# Report contract v1

`schema` is `rudy-netproof/report-v1`; `version` identifies the tool. Successful reports have `complete: true`. Invalid input or exhausted budgets produce no report and exit `2`. File-write failure can leave an incomplete new file and is also exit `2`; a report file's existence alone is not success.

## Analysis

`summary` covers all rules and disjoint decision regions. `allowedTuples` and `deniedTuples` are exact decimal strings. A rule row includes `matchedTuples`, `reachableTuples`, `status`, a nullable `reachableWitness`, and its `blockers`. Each blocker has the actual earlier first-match owner, action, exact blocked count, and representative witness. Blocker counts are complete internally; `omittedBlockers` explicitly signals truncated display. `omittedRules` does the same for rule rows. Fully shadowed counts and gates are independent of displayed rows.

## Comparison

`equivalent` is true only when there are no differing actions anywhere in the shared declared domain. `summary.openedTuples`, `closedTuples`, and `changedRegions` are complete. `changes` contains displayed disjoint intervals, their exact tuple counts, `beforeRule`, `afterRule`, `change` (`opened` or `closed`), and a witness. `omittedChanges` counts the remaining intervals. Region counts describe a particular symbolic decomposition, not a canonical number of logical policy changes.

An interval row stores inclusive address strings and port endpoints. Its `tuples` can be independently checked by multiplying `(upper - lower + 1)` across the four dimensions. The protocol is fixed per region and does not need an additional multiplier.

Replay any witness with `netproof explain POLICY --source ... --destination ... --source-port ... --destination-port ... --protocol ... --format json` against each input policy. Its action and decisive owner must match the comparison row. No packet is sent. `$default` is the reserved final owner and cannot be a user rule ID.

## Explanation

`packet`, `action`, and `decisiveRule` give the outcome for one tuple. `matchingRules` lists every matching rule in policy order; only the first has `decisive: true`. If none match, the default decides. A packet outside the policy family scope is an error rather than an implicit deny.

`budget` records the deterministic box-pair operation and generated-region counters for complete analyses/comparisons. It does not measure memory allocation, wall time, network exposure, or security confidence. Names, rule IDs, addresses, and ports are not redacted.
