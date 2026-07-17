---
applyTo:
  - "felix/collector/**"
---

# Felix flow-logs collector

Architecture, the verdict-gating invariant, flow sampling, and per-section
review criteria for Felix's flow-logs collector live in
[`felix/design/flow-logs-collector.md`](../../felix/design/flow-logs-collector.md),
indexed from [`felix/DESIGN.md`](../../felix/DESIGN.md). Review notes are
embedded inline at the end of each section.

Before writing code (Copilot coding agent) or reviewing a PR (Copilot code
review) in any file matched by this instruction's `applyTo`, read the relevant
section(s) of
[`flow-logs-collector.md`](../../felix/design/flow-logs-collector.md) and apply
the review notes embedded there. Follow links — the NFLOG match primitive is
covered by [`dataplane.md`](../../felix/design/dataplane.md), the eBPF flow-log
path by [`bpf-observability.md`](../../felix/design/bpf-observability.md), and
the Goldmane `Flow` proto by `goldmane/DESIGN.md`.

## Update rule

The repo-wide doc-update rule and its exemptions
([`.github/copilot-instructions.md` → Documentation map](../copilot-instructions.md),
mirrored in [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md)) apply. For the
collector, "changes how it works" means: a change to the collection source
wiring or the verdict-gating invariant; a change to the sampling mechanism, its
config surface, or the `sampling_rate` semantics; or a change to the eBPF
1-in-1 guarantee. Update
[`flow-logs-collector.md`](../../felix/design/flow-logs-collector.md) in the
same PR (and `goldmane/DESIGN.md` / [`dataplane.md`](../../felix/design/dataplane.md)
when the proto or the NFLOG match primitive changes).
