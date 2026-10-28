# Security boundaries

NetProof is an offline model-analysis preview. It reads explicitly named regular JSON files, never opens a network socket, never changes a firewall, and never executes input content. It does not test network targets or establish that an installed firewall implements the model.

Use policies you are authorized to review. Reports disclose policy names, address ranges, ports, and rule IDs. There is no anonymization or credential discovery, and raw production policy reports should not be published casually.

Input is limited to 8 MiB, 32 nesting levels, and 500 rules. Unknown fields, duplicate keys/IDs, unsupported protocols and noncanonical networks are rejected. Symbolic expansion and comparison have explicit operation/fragment budgets, and output is capped at 16 MiB. These are application limits, not whole-process memory/time guarantees. Use OS isolation and memory/time controls for unfamiliar inputs. Parser and core implementation defects remain possible.

Reports use exclusive new-file creation. Existing files and links are refused; a failed disk write can leave a new incomplete report. Check exit status before treating output as evidence. Standard output can be redirected by the caller, whose shell then controls file replacement semantics.

HTML contains no JavaScript or external assets. All policy-derived markup is escaped and a restrictive CSP is supplied. Model witnesses are data and never transmitted as packets.

Report a suspected vulnerability through the repository's private reporting option when available, or contact the maintainer through the contact information on the GitHub profile. Do not put production policy content or credentials in public issues.
