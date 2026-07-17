<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Felix flow-logs collector

How Felix turns dataplane activity into the flow logs consumed by Goldmane
(and by local consumers such as Whisker over a unix socket), and how flow
**sampling** bounds the CPU that collection costs on the iptables/nftables
dataplane.

The rule-generation side of sampling (the NFLOG match primitive) lives in the
Linux dataplane and is covered by [`dataplane.md`](./dataplane.md); the eBPF
flow-log path is covered by
[`bpf-observability.md`](./bpf-observability.md). The full set of sub-designs
is listed in [`felix/DESIGN.md`](../DESIGN.md).

## Collection pipeline (iptables/nftables)

The collector (`felix/collector/`) is fed by **two independent sources**,
selected in `felix/dataplane/linux/int_dataplane.go` by `!config.BPFEnabled`:

- **NFLOG** (`collector.NewNFLogReader`, `felix/collector/iptables.go`) — the
  kernel emits a netlink notification when a packet hits an NFLOG verdict rule.
  This is the source of **policy/rule attribution** (the `RuleID`).
- **conntrack polling** (`collector.NewNetLinkConntrackReader`) — periodically
  dumps the conntrack table for accurate per-connection packet/byte counters.

Both feed a single per-tuple cache `collector.epStats` (`collector.go`). An
entry is created by whichever source sees the tuple first; conntrack fills the
counters, NFLOG fills the rule trace and the verdict. Entries flow through
`flowlog.Aggregator` (keyed by `FlowMeta`) to the reporters — the Goldmane
gRPC reporter (`felix/collector/goldmane/client.go`) and the local socket
reporter — both of which serialise via `ConvertFlowlogToGoldmane` into the
Goldmane `Flow` proto (`goldmane/proto/api.proto`).

Established connections are short-circuited by an earlier conntrack
`ESTABLISHED,RELATED` accept and never reach the policy-verdict NFLOG rules, so
**NFLOG fires ~once per new connection**. This is why collection CPU scales
with *new-connections/sec* rather than with packet rate or distinct-flow count.

### The verdict-gating invariant

Flow-log emission is gated **exclusively** on an NFLOG-sourced verdict. Every
`LogMetrics` call in `collector.sendMetrics` is guarded by
`RuleTrace.FoundVerdict()`, and `verdictIdx` is advanced only by NFLOG rule-trace
processing (`felix/collector/stats.go`). A connection seen by conntrack but never
by NFLOG is created, counted, and eventually expired **without ever emitting a
flow log** — there is no `__UNKNOWN__`/deny-by-default placeholder. This holds on
normal report, forced report, and expiry alike.

This invariant is what makes NFLOG sampling a *statistically sound* flow sampler
(see below): dropping NFLOG for a connection drops its flow log entirely, rather
than emitting a mis-attributed one.

> **Review notes.**
> - Do not add a code path that emits a flow log without a verdict — it would
>   break the sampling contract (non-sampled flows must stay silent) and change
>   long-standing behaviour. If you need conntrack-only flows reported, that is a
>   deliberate design change, not an incidental one.
> - `IsBPFDataplane` in the collector config selects conntrack timeout values
>   only. It must not gate *which* flows are collected; the BPF/iptables
>   divergence lives at the source layer in `int_dataplane.go`, not inside the
>   shared collector.

## Flow sampling

### Motivation

On the iptables/NFLOG dataplane, collection cost decomposes cleanly into a fixed
term plus a term proportional to new-connection churn. Benchmarking (per-Felix
CPU, collection ON vs OFF across a 100 → 10 000 new-conns/sec staircase) gives:

```
Felix collection CPU  ≈  ~0.6 core (fixed)  +  ~1.0 core per 1 000 new-conns/sec
Baseline (collection off) ≈ 0.11 core, flat across a 100× churn sweep
```

| new-conns/s | Felix ON | Felix OFF | Δ (collection) |
|---:|---:|---:|---:|
| 100 | 0.84 | 0.11 | 0.73 |
| 500 | 1.38 | 0.11 | 1.27 |
| 2 000 | 3.12 | 0.11 | 3.01 |
| 10 000 | 10.86 | 0.11 | 10.74 |

Two properties matter:

- The **OFF series is flat** across the whole sweep — connections traversing the
  dataplane are nearly free to Felix; essentially all churn-proportional cost is
  NFLOG *ingest* processing (netlink recv, parse, `RuleID`/endpoint lookup, cache
  update), which happens per new connection.
- The **export side is fixed** — delivered flows held ~90/s across the sweep,
  because Goldmane collapses churn into a small, fixed set of `FlowKey`s. Cost
  tracks new-connections/sec, not distinct-flow width.

### Design

Sample **1-in-N new connections** before the NFLOG verdict fires, so only 1-in-N
new connections produce a notification. The knob is `FlowLogsSamplingRate`
(FelixConfiguration, integer ≥ 1; `1` = no sampling). A random per-new-connection
match is added to every NFLOG verdict rule when N > 1:

- iptables: `-m conntrack --ctstate NEW -m statistic --mode random --probability <1/N>`
- nftables: `ct state new numgen random mod <N> == 0`

Restricting to `ctstate NEW` moves the sampling decision to connection setup —
the gate is evaluated on the connection-initiating packet(s), not the whole
packet stream. Random mode (vs deterministic nth) keeps the 1-in-N draw
independent per connection. See "Sampling model" below for why this matters.

The match is applied uniformly at all NFLOG emission sites — per-policy
allow/pass/deny (`felix/rules/policy.go`) and end-of-tier / no-profile-match
(`felix/rules/endpoints.go`) — gated on `rules.Config.FlowLogsSamplingRate`. At
N = 1 no match is emitted, so the generated rules are byte-identical to the
pre-feature output.

### Sampling model and its impacts

Mechanically this is packet sampling — `statistic`/`numgen` is a per-packet
gate. But the `ctstate NEW` restriction plus the conntrack fast-path (which
short-circuits established packets before they reach the verdict rules) mean the
gate only ever sees the connection-initiating packets, ~one per flow. The
sampled substream is therefore ~one packet per connection, which makes this
**flow-based sampling** (analogous to IPFIX flow selection, RFC 7014) rather
than the per-packet sampling of sFlow / sampled NetFlow.

Two properties follow from the collection pipeline above — flow logs are emitted
only for connections whose setup packet was sampled, and a reported connection's
counts come from **conntrack** (the full, exact counters), not from the sampled
packet:

- **Per-flow counts are exact**, not thinned by 1/N. A reported flow is a true,
  complete connection record.
- **Detection is independent of flow size.** A one-packet flow and a 10 GB flow
  are each sampled with probability ~1/N. Contrast sFlow/NetFlow, where a flow
  is seen with probability `1-(1-1/N)^packets` — biased toward large flows and
  prone to missing small/short ones.
- **Estimation:** `#flows ≈ #reported × N` (unbiased); aggregate volume
  `≈ Σ(reported counts) × N`. Individual records must **not** be scaled.

The trade-off is the **elephant blind spot**: because detection is
size-independent, a large flow whose setup packet is not sampled is invisible
for its whole life (each flow missed with probability `1-1/N`). sFlow's size
bias would almost always catch it. This is acceptable for policy-attributed flow
visibility (Goldmane's purpose) but means sampled data cannot guarantee every
large talker is seen; aggregate volume estimates stay unbiased regardless.

Caveat: the exact-counts property holds for conntrack-tracked connections. For
denied or otherwise untracked traffic there are no conntrack counters and the
collector falls back to NFLOG-hit counts, which are packet-sampled (thinned) for
that subset.

### The `sampling_rate` field

Each reported flow carries the rate it was sampled at so consumers can
extrapolate. `sampling_rate` is a per-`Flow` field on the Goldmane proto (not on
`FlowKey` — keying on it would fragment aggregation). Because this is flow (not
packet) sampling, a record with `sampling_rate = N` is one *exact* connection
that stands in for ~N actual connections: scale **flow counts and aggregate
sums** by N to estimate population totals, but do **not** scale an individual
record's counts — they are already true. `N = 1` means no sampling. It is
stamped in `ConvertFlowlogToGoldmane`.

Scope: Felix emits this on every flow (gRPC to Goldmane and the local socket
reporter). Goldmane's `BucketRing` aggregation does not yet retain or apply it,
so its `Flows`/`Statistics` query output currently drops the field — applying
the per-flow multiplier before summing is future work.

### eBPF is always 1-in-1

The eBPF dataplane collects flow logs from a ring buffer + BPF conntrack scanner
and never uses the `felix/rules/` NFLOG path, so the sampling match is
structurally invisible to it. As a second, explicit guarantee, the collector
stamps `sampling_rate = 1` whenever `IsBPFDataplane` is set, regardless of the
configured rate.

### Expected CPU impact, and its ceiling

Sampling reduces the churn-proportional NFLOG term by ~1/N; the fixed ~0.6-core
term and the ~0.11-core baseline are unchanged. Modelling
`Felix(N, C) ≈ 0.71 + 1.0·(C/1000)/N` cores gives the reduction versus today
(N = 1):

| new-conns/s | N=2 | N=10 | N=100 | ceiling (N→∞) |
|---:|---:|---:|---:|---:|
| 100 | ~9% | ~14% | ~15% | 15% |
| 500 | ~30% | ~45% | ~48% | 48% |
| 2 000 | ~45% | ~71% | ~77% | 77% |
| 10 000 | ~47% | ~84% | ~93% | 93% |

The benefit is large only where the variable term dominates (high churn); at low
churn the fixed collection floor caps it. That floor — conntrack polling,
`epStats` sweep, aggregation flush, export — is **not** reduced by sampling:
non-sampled connections are still created from conntrack, counted, and swept;
they simply never emit a flow log. The table is therefore an **upper bound** —
the single benchmarked churn term lumps NFLOG ingest together with any
conntrack/`epStats` per-flow cost, and only the NFLOG part is reducible.

> **Review notes.**
> - N = 1 must be a true no-op: no sampling match emitted, generated rules
>   byte-identical to pre-feature output. Guard this with a rules UT — it is the
>   backward-compat contract for existing deployments.
> - Apply the match at **every** NFLOG verdict site, or allow-flows and
>   deny-flows sample at different rates and the extrapolation is biased.
> - `sampling_rate` belongs on `Flow`, never on `FlowKey`.
> - This is flow (not packet) sampling: per-flow counts are exact, so consumers
>   scale population/aggregate totals by N, never an individual record. Do not
>   describe it as sFlow-style, and preserve the `ctstate NEW` + conntrack-counts
>   basis that makes it flow-based — losing either turns it into biased packet
>   sampling.
> - Any claim about CPU savings must state the churn regime and that the fixed
>   floor is not reduced — do not quote a headline percentage unqualified.
> - The reduction table is a model, not a measurement; the definitive figure
>   comes from running the collection benchmark with the sampled arm.

## Keep this in sync

Update this doc in the same PR when: the collection source wiring or the
verdict-gating invariant changes; the sampling mechanism, its config surface, or
the `sampling_rate` semantics change; or the eBPF 1-in-1 guarantee changes. A
change to the Goldmane `Flow` proto also updates `goldmane/DESIGN.md`; a change
to the NFLOG match primitive also updates [`dataplane.md`](./dataplane.md).
