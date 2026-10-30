<!-- SPDX-License-Identifier: Apache-2.0 -->
<!--
  Copyright 2026 the MANTLE Receipts contributors.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at verifier/LICENSE in this
  repository, or at http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->

# MANTLE receipt and ledger format

This document specifies the on-disk formats an independent verifier
needs: the kernel receipt (`jl.receipt.v1`), the Meaning IR
(`jl.meaning-ir.v1`), the ledger entry (`jl.mantle-ledger.v1`), and
the seal. It is Apache-2.0 (like `verifier/`) so anyone can implement
a checker. The normative implementation is
`verifier/mantle-verify.mjs`.

## Canonical JSON and content addresses

All hashes are over **canonical JSON**: object keys sorted ascending,
arrays in order, `JSON.stringify` of the normalized value. Numbers
must be finite (`-0` normalizes to `0`); `undefined` anywhere is an
error. Digest: SHA-256, lowercase hex.

```
contentAddress(value) = "sha256:" + sha256hex(canonicalJSON(value))
sha256(value)         = sha256hex(value)              if value is a string or bytes
                      = sha256hex(canonicalJSON(value)) otherwise
```

Decimal values in receipts are always **strings** (`"123.45"`) plus an
integer `scale`; floats never appear in hashed structures.

## Receipt (`jl.receipt.v1`)

Produced by the engine's `makeReceipt`; verifiers treat it as data:

```json
{
  "receipt_version": "jl.receipt.v1",
  "engine": "MANTLE_RECEIPTS",
  "operation": "ask | verify-claim | explain-change | history | import | compute",
  "input_hash": "sha256:… (contentAddress of the recorded input)",
  "output_hash": "sha256:… (contentAddress of the output object)",
  "verdict": "CERTIFIED | REFUSED | VERIFIED | MATCH | MISMATCH | MATCH_WITHIN_TOLERANCE",
  "reasons": ["closed-list refusal codes, sorted, deduplicated"],
  "evidence_hashes": ["sha256:… contentAddress of each evidence receipt, sorted"],
  "authority_hash": null,
  "previous_receipt_hash": null,
  "metadata": {},
  "receipt_hash": "sha256:… contentAddress of all fields above"
}
```

Receipts are **pure functions of their inputs**: `previous` is always
null in MANTLE Receipts, so the same question produces a
byte-identical receipt (and `receipt_hash`) every time. Ordering and
tamper-evidence live in the ledger entry, not in the receipt.

Verification of one receipt: recompute `contentAddress` of the
receipt without `receipt_hash` and compare.

## Meaning IR (`jl.meaning-ir.v1`)

One object per metric per version; the recorded input of every Ask:

```json
{
  "ir_version": "jl.meaning-ir.v1",
  "object_id": "revenue",
  "label": "Revenue",
  "synonyms": ["sales"],
  "unit": "USD",
  "time_field": "order_date",
  "definition": {
    "operation": "sum | count | count_non_null | count_distinct | average | min | max | ratio | arith",
    "field": "amount",
    "filters": [{ "field": "status", "operator": "neq", "value": "refunded" }]
  },
  "scope": null,
  "exclusions": [],
  "source": {
    "format": "dbt-metricflow | atscale-sml | snowflake-semantic-view | apache-ossie",
    "repo": "<repo name, never an absolute path>",
    "commit": "<40-hex git sha>",
    "path": "models/metrics.yml",
    "file_sha256": "<hex sha256 of the raw file bytes at that commit>",
    "pointer": "metrics[name=revenue]"
  }
}
```

`ratio` definitions carry `numerator` and `denominator` sub-definitions
(`{operation: sum|count|count_non_null, field, filters}`) instead of
`field`. Filter operators: `eq neq in not_in gt gte lt lte is_null
is_not_null`.

`arith` definitions (FROGA V1.1, only where V1 refused) carry
`operands` and `expr` instead of `field`:

```json
{ "operation": "arith",
  "operands": { "<name>": { "object_id": "<referenced metric>", "filters": [] } },
  "expr": { "op": "+|-|*|/", "args": [<AST>, <AST>] },
  "filters": [] }
```

AST nodes: `{"ref": "<operand name>"}`, `{"lit": "<canonical
decimal>"}`, `{"op": "+|-|*|/", "args": [a, b]}`, `{"op": "neg",
"args": [a]}`, `{"op": "null_if_empty", "guards": ["<name>", …],
"then": <AST>}`. Operand keys are the source's reference names
verbatim. Operands are references resolved at ask time,
bitemporally — never inlined copies.

### Time intelligence (`ti`) — FROGA V1.2-b

A `ti` definition reads a base metric over a DIFFERENT window than the
one asked. It is used only where V1.1 refused:

```json
{ "operation": "ti",
  "kind": "shift | to_date | day_offset",
  "grain": "year | quarter | month",     // shift and to_date only
  "unit": "day | week | year",           // day_offset only
  "n": 1,                                 // shift and day_offset only
  "base": { "object_id": "<metric>" },    // or an inline base — below
  "filters": [] }
```

- **`shift`** moves the ask window back by `n` grain units: March 2026
  at shift year 1 is March 2025. **`to_date`** widens it to the grain
  period that holds the window's last instant: a March window at year
  grain is `[2026-01-01, 2026-04-01)`. **`day_offset`** is dbt's
  day-level offset, which shifts the DAILY data and then aggregates —
  it counts days, not months, so it has a unit and never rounds to a
  month.
- `base` is a **bitemporal reference**, resolved once at the Ask's
  `(valid_at, known_at)` exactly as a plain Ask of the base would
  resolve it. That one definition is applied to the shifted rows, so a
  prior-year comparison is like for like.
- A base may instead be **inline** — `"base": { "definition": { … } }`
  — carrying the definition to read rather than naming a metric. A dbt
  cumulative metric uses this: its base is a **measure**, and a measure
  is not a metric. The inline definition is the measure's aggregate or
  expression on its semantic model, plus only that cumulative metric's
  own filter. The metric-reference form keeps its exact bytes, so a
  `ti` that names a metric does not move its structural hash.
- Because an inline base names no metric, the receipt's `ti_windows[]`
  entry carries `"base": null` for it. That is the honest value: there
  is no metric to name. The definition itself is in the receipt's
  `meaning`, so the window can still be recomputed and checked.
- A `ti` definition may also ride on an **operand** of an `arith`
  definition, so `(m − PY(m)) / PY(m)` works. The operand's `ti` key
  is present only when there is one, so every other operand keeps its
  exact shape and its structural hash does not move.

An IR may carry a top-level **`calendar`** field: the calendar
declaration it relied on, as `"<dimension unique_name>.<hierarchy
unique_name>=gregorian"`. It is present only when there is one. It is
part of the structural hash, because a metric that changes calendar is
a different metric.
### Member navigation and member slices — FROGA V1.3

Two new `ti` kinds, and one new expression node. Both are present only
on their own kinds, so every V1.2-b definition keeps its exact bytes.

```json
{ "operation": "ti",
  "kind": "member_nav | member_set",
  "nav":  { "type": "prev | next | lag | forward | backward", "n": 1, "grain": null },
  "set":  { "type": "lag_range | periods_to_date | period",
            "from": 2, "to": 0, "level": "Month", "grain": "month",
            "nav": null, "anchor": null },
  "aggregate": "sum | avg",              // member_set only
  "grains": [ "month", "quarter", "year" ],
  "base": { "object_id": "<metric>" },
  "filters": [] }
```

- **`member_nav`** reads the base over a period RELATIVE TO THE CURRENT
  MEMBER — the period the Ask declares through its `period` field.
  `nav.type` is `prev` (1 back), `next` (1 forward), `lag` (n back) or
  `forward` (a `ParallelPeriod` with n ≤ −1: |n| periods forward at the
  level it names). `nav.grain` is the grain of the STEP the navigation
  names; `null` means the Ask's grain.
- **`member_set`** reads the base over SEVERAL periods and aggregates
  them: `sum` adds them, `avg` is the mean over the periods where the
  base is **non-empty** (MDX semantics — empty cells are excluded, not
  counted as zero). A set whose every period is empty is `null`, not
  zero.
- The three set types: **`lag_range`** reads the periods from `from`
  back to `to` back, inclusive (`from` ≥ `to`). **`periods_to_date`**
  reads the level's period, period by period, through the current
  member. **`period`** is a set of ONE period, named by `nav` — the
  `Avg(<navigation>, M)` shape.
- The set spec always carries **all seven** of its fields — `type`,
  `from`, `to`, `level`, `grain`, `nav`, `anchor` — and a field that
  does not apply is `null`, not absent. `nav` and `anchor` are
  themselves navigations, `{type, n, grain}`.
- An **anchor** is the period a to-date runs to. Its type is `backward`
  (MDX's n > 0: n periods back) or `forward` (n ≤ −1: |n| periods
  forward), and it must name the same hierarchy the to-date reads.
  `backward` appears only as an anchor; a top-level navigation is
  `prev`, `next`, `lag` or `forward`.
- **`grains`** are the grains the hierarchy has levels for. The Ask
  checks its own grain against that list, and refuses
  `UNSUPPORTED:TIME_LEVEL_UNRESOLVED` when the hierarchy has no level
  there. The list is import-resolved, so the Ask's grain never has to
  be guessed from a level's name.
- `base` is a bitemporal reference, exactly as for a V1.2-b `ti`: the
  base's definition is resolved once, at the Ask's `(valid_at,
  known_at)`, and that one definition is applied to every period.

A **member slice** — a tuple of a member and a measure, `([Measures].
[X], H.&[k])` — is not a `ti` kind. It is the measure with ONE extra
filter, so it is an `arith` whose operand carries that filter:

```json
{ "operation": "arith",
  "operands": {
    "Store Returns Count__slice": {
      "object_id": "Store Returns Count",
      "filters": [ { "field": "returns_time_tier", "operator": "eq",
                     "value": "31-60 days" } ] }
  },
  "expr": { "ref": "Store Returns Count__slice" },
  "filters": [] }
```

The operand's `object_id` is a **bitemporal reference**, so the
measure's definition is resolved at ask time and nothing is inlined.
The filter is the member's key column equal to the member's key, which
is only possible when that column is a single column of the measure's
OWN dataset — otherwise the slice would need a join, and it refuses
`UNSUPPORTED:CROSS_DATASET_EXPRESSION`.

A member reference may name its level in **two parts** —
`[Dim].[X].&[k]` — and `X` is read either as a level of that dimension
(a `level_attributes[].unique_name`) or as a hierarchy that has exactly
one level. Two readings that name the **same** level are one member;
two readings that name **different** levels are `UNSUPPORTED:MDX_TUPLE`.

The MDX shape `IIF(IsEmpty(<slice>), 0, <slice>)` is a new expression
node beside the V1 `null_if_empty`:

```json
{ "op": "zero_if_empty",
  "guards": [ "Store Returns Count__slice" ],
  "then": { "ref": "Store Returns Count__slice" } }
```

`null_if_empty` makes an empty cell **null** (the V1 rule, and there is
no ELSE: nothing is ever invented). `zero_if_empty` makes it **zero**,
exactly, which is what the MDX says.

The **structural hash** of a meaning is
`contentAddress({object_id, definition, scope, exclusions, unit,
time_field})` — `label`, `synonyms`, and `source` are excluded, so
renames and file moves are not meaning changes. A `calendar`, when
present, is included in the hash.

Bitemporal version rows (in HISTORY receipt outputs) add:
`{object_id, version: "v1…", valid_from, valid_to, known_from,
known_to, structural_hash, supported, reason, commit,
effective_from_source, ir, source}` with half-open intervals.
Timestamps are canonical UTC ISO-8601 with millisecond precision.

## Ledger entry (`jl.mantle-ledger.v1`)

`<dir>/ledger.jsonl` holds one JSON object per line (canonical JSON,
`\n`-terminated), one entry per appended result — asks, claims,
changes, and history builds, CERTIFIED and REFUSED alike:

```json
{
  "entry_version": "jl.mantle-ledger.v1",
  "seq": 0,
  "receipt": { "…": "the deterministic receipt, unchanged" },
  "receipt_hash": "<receipt.receipt_hash>",
  "input": "the exact object whose contentAddress is receipt.input_hash",
  "output": "the exact object whose contentAddress is receipt.output_hash",
  "evidence": ["full evidence receipt objects"],
  "previous_entry_hash": null,
  "entry_hash": "sha256:…"
}
```

- `seq` starts at 0 and increments by 1 per line.
- `previous_entry_hash` is the prior line's `entry_hash`, null at seq 0.
- `entry_hash = contentAddress({entry_version, seq, receipt,
  receipt_hash, previous_entry_hash})` — exactly those five fields.
  The recorded `input`/`output`/`evidence` ride on the same line;
  their integrity is bound by the receipt's own
  `input_hash`/`output_hash`/`evidence_hashes`, which a verifier must
  also check.

Chain values used by seals: `ledger_head` = the last `entry_hash`;
`chain_hash = sha256(JSON array of every entry_hash in order)`.

Appends are `O_APPEND` + fsync, and a conforming writer refuses to
append to a ledger that does not verify.

## Ask / claim / change records

- **Ask input:** `{question, meaning_ir, meaning_version,
  data_sha256}`. `question` is the canonical Ask with the resolved
  `valid_at`; `data` inside it carries only `{name, sha256, dataset}`
  (never a filesystem path).
- **Ask output:** `{system: "MANTLE_RECEIPTS", version: "1.0.0",
  verdict, reasons, question, meaning, data, answer}` where
  `meaning = {object_id, version, structural_hash, effective_from,
  known_from, source}`, `data = {name, sha256, rows_scanned,
  rows_matched}`, and `answer = {groups: [{key, value, scale}]}`.
  Meaning-stage refusals have `data: null` and `answer: null`.
  For `arith` metrics only, `meaning` gains `inputs:
  [{object_id, version, structural_hash}]` (every resolved input,
  recursively flattened, sorted, deduplicated) and the recorded
  Ask input gains `input_defs` (the flattened transitive input
  IRs, what replay needs). V1 metrics' records are unchanged.
- **Time intelligence (FROGA V1.2-b):** an Ask or change over a `ti`
  metric gains three fields. `ti_definition_policy` is
  `"like_for_like"`: the base was resolved once, at the Ask's own
  `(valid_at, known_at)`, and that one definition was applied to the
  shifted rows. `ti_windows` lists every window actually read, in
  order:

  ```json
  { "kind": "shift | to_date | day_offset",
    "semantics": "mdx_period_shift | dbt_day_offset | to_date",
    "base": "<metric>",              // null for an inline base
    "window": { "start": "<iso>", "end": "<iso>" },
    "grain": "year | quarter | month",   // shift and to_date
    "unit": "day | week | year",          // day_offset
    "n": 1 }
  ```

  `semantics` names the semantics the window was computed with: MDX
  member semantics for a grain shift, dbt's day-level offset for a day
  offset, and a to-date window for a to-date. `ti_semantics` appears at
  the top level of the output when every window in the receipt used the
  same semantics; each entry in `ti_windows` always names its own. The
  windows are in the receipt so that an EMPTY prior period is visible
  rather than hidden: a prior year with no rows answers zero, and the
  receipt says which window was empty.
- **The period (FROGA V1.3):** an Ask may carry `period: { "grain":
  "year" | "quarter" | "month" }`. It names the CURRENT MEMBER a member
  navigation is relative to, and the Ask's window must then be exactly
  one whole period at that grain (`WINDOW_NOT_ONE_PERIOD` otherwise).
  Without it, a current-member-relative navigation refuses
  `NEEDS_PERIOD` — the period is never inferred from the length of a
  window. The field is recorded in the canonical question **only when
  it is present**, so every V1.2-b question keeps its exact bytes.
  A member navigation's receipt names its semantics
  `ti_semantics: "mdx_member_navigation"`, and its `ti_windows` entries
  carry `kind: "member_nav" | "member_set"` with the `nav` or `set`
  that named them.
- **Claim (`verify-claim`)** input: `{claimed, tolerance,
  ask_receipt_hash}`; evidence is the Ask receipt. Output adds
  `claim_verdict`, per-group exact `deltas`, and
  `missing_groups`/`extra_groups`.
- **Change (`explain-change`)** input: `{request, meaning_irs: {a,
  b}, data_sha256}`; output carries the three computed values and
  `business_effect`, `definition_effect`, `reported_change` as
  `{value, scale}` decimals satisfying business + definition =
  reported exactly.
- **History** input: `{repo, head, format}`; output: `{versions,
  gaps, labels, report}`; evidence is one import receipt per commit
  (REFUSED with `IMPORT_FAILED` for commits that did not import).
  Whole-commit gaps are `{from, to, commit}`. Per-file object gaps
  (FROGA V1.1 M6) add sorted `object_ids` and `paths`. `report` is
  `{failed_commits, ignored_annotations}`, plus `failed_files:
  [{commit, path}]` only when non-empty.
- **Compute** receipts appear only as evidence: input binds the
  definition, window, grouping, filters, and `data_sha256`.

## Seal (`seals.jsonl`)

One JSON object per line:

```json
{
  "target": { "ledger_head": "<last entry_hash>", "length": 7, "chain_hash": "<hex>" },
  "approval": {
    "protocol": "jl.semantic-authority.v1",
    "actor": "<receipts dir actor>",
    "purpose": "mantle-receipts-seal",
    "target_hash": "sha256:… contentAddress(target)",
    "public_key_fingerprint": "sha256:<sha256hex of the SPKI PEM text>",
    "signature": "<base64 Ed25519 over canonicalJSON({protocol, actor, purpose, target_hash})>"
  }
}
```

A seal covers the ledger **prefix** of `target.length` entries: it
stays valid as the ledger grows. The private key (`keys/
owner-private.pem`, mode 0600) never appears in any output.

## Proof packet (`jl.froga-proof-packet.v1`)

One file an auditor can check on their own, with free tools and
nothing else. Written by `mantle receipts prove <dir> <request.json>
--out <packet.json> [--include-data]`; checked by `node
verifier/mantle-verify.mjs --packet <packet.json>`.

The packet is an **export**, never a second opinion: the request runs
through the normal pipeline, so it is appended to the ledger like any
other result, and only then is the ledger sealed and the packet cut.

The file is canonical JSON with sorted keys, and `packet_hash` is the
last member so a reader sees the address before the body:

```json
{
  "packet_version": "jl.froga-proof-packet.v1",
  "result": {
    "entry_version": "jl.mantle-ledger.v1",
    "seq": 3,
    "receipt": { "…": "the kernel receipt, exactly as in the ledger" },
    "receipt_hash": "sha256:…",
    "input": { "…": "the recorded input" },
    "output": { "…": "the recorded output" },
    "evidence": [ "…": "the evidence receipts" ],
    "previous_entry_hash": "sha256:… | null",
    "entry_hash": "sha256:…"
  },
  "chain": { "entry_hashes": [ "sha256:…", "…", "sha256:…" ] },
  "seal": { "target": { "…": "as stored in seals.jsonl" },
            "approval": { "…": "as stored in seals.jsonl" } },
  "public_key": { "pem": "-----BEGIN PUBLIC KEY-----…",
                  "fingerprint": "sha256:<sha256hex of the SPKI PEM text>" },
  "definitions": [
    { "object_id": "revenue",
      "version": "v2",
      "structural_hash": "sha256:…",
      "valid_from": "<effective instant>",
      "known_from": "<knowledge instant>",
      "ir": { "…": "the full Meaning IR" },
      "source": { "repo": "acme", "commit": "<sha>", "path": "metrics.yml",
                  "file_sha256": "<hex>",
                  "bytes_b64": "<base64 of the exact file bytes at that commit>" } }
  ],
  "history": [
    { "object_id": "revenue", "version": "v1",
      "valid_from": "…", "valid_to": "…",
      "known_from": "…", "known_to": "…",
      "structural_hash": "sha256:…", "supported": true, "reason": null,
      "commit": "<sha>", "effective_from_source": "commit_time",
      "ir": { "…": "the IR of that version" },
      "source": { "…": "where that version came from" } }
  ],
  "data": { "name": "orders.csv", "sha256": "<hex>",
            "rows_scanned": 2000, "rows_matched": 555,
            "bytes_b64": "<base64 data bytes, or null>" },
  "packet_hash": "sha256:… contentAddress of every field above"
}
```

Rules a packet always obeys:

- `chain.entry_hashes` is **every** entry hash in the ledger, in order.
  `chain.entry_hashes[result.seq] === result.entry_hash`, the chain
  hash recomputed from it equals `seal.target.chain_hash`, the last
  hash equals `seal.target.ledger_head`, and the length matches.
- `definitions` holds every metric version the answer used — the asked
  metric and, for an expression, every resolved input, recursively.
  `history` holds every version-table row of those objects, so an
  outsider sees v1 → v2 and both timelines.
- `source.bytes_b64` is the **exact source file bytes at that commit**,
  and hashes to `source.file_sha256`.
- `data.bytes_b64` is `null` unless the packet was cut with
  `--include-data`. Without that flag the data is described (name,
  hash, row counts) but not carried.
- The **private key never appears**. Only the public PEM does.
- `definitions` is sorted by `(object_id, structural_hash)` and
  `history` by `(object_id, known_from, valid_from, version, valid_to,
  known_to)`; a section in any other order was arranged by hand.

### What a packet verifier must check

1. `packet_hash` recomputes over the whole body.
2. The result entry stands on its own: receipt hash, entry hash, and
   the input/output/evidence hash bindings.
3. Inclusion: the result sits at its `seq` in the chain; the chain
   hash, head and length match the seal's target.
4. The seal's signature over that target verifies against the public
   key. With `--pubkey`, that key must match the packet's fingerprint
   (`PUBKEY_MISMATCH` otherwise); without it, the verifier uses the
   embedded key and says so plainly, because a packet can carry its
   own key.
5. Each definition's source bytes hash to `source.file_sha256`, each
   IR's structural hash recomputes, and the definition the receipt used
   is among them.
6. Knowledge time: the version the receipt used is the one the
   `history` rows select at `(valid_at, known_at)`, selected by the
   verifier's own interval code.
7. Replay, when the data is available (embedded, or supplied with
   `--data`): the data hash matches and the verifier's own compute
   reproduces the answer exactly — for asks, claims and changes alike.

Exit 0 when valid; exit 2 with the first failing check and its reason
when not; exit 1 when the input cannot be read.

## What a verifier must check

1. Every line parses; `entry_version` is `jl.mantle-ledger.v1`.
2. `seq` equals the line index; `previous_entry_hash` links to the
   prior line's `entry_hash` (null at seq 0).
3. Each `entry_hash` recomputes from its five fields.
4. `entry.receipt_hash` equals `entry.receipt.receipt_hash`; each
   receipt's own hash recomputes; `input`/`output`/`evidence` hash
   bindings hold; every evidence receipt's hash recomputes.
5. With a public key: every seal's target matches the covered prefix
   (head + chain_hash), fingerprint matches the key, and the Ed25519
   signature verifies.
6. Optionally, **replay**: for every CERTIFIED Ask entry, load the
   data file named by `output.data.name`, require its bytes to hash
   to `output.data.sha256`, recompute the answer from
   `input.meaning_ir` + `input.question` with an independent exact
   implementation, and compare groups and row counts exactly.

Exit 0 when valid; exit 2 with the first failing line index and
reason when not.
