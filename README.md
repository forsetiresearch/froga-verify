# froga-verify

Check a number someone hands you, without trusting them or us.

`froga-verify` is a single-file, dependency-free verifier for **FROGA proof packets**: one JSON file that carries an
answer (for example "March 2026 revenue = 139,970.29"), the exact metric definition that produced it, when that
definition took effect and when it was recorded, a hash-chained and signed ledger entry, and optionally the data.
The verifier re-derives everything with its own code and says **valid** or names the first thing that is wrong.

```
node froga-verify.mjs --packet examples/proof-packet.json --text            # exit 0, "VERDICT: valid."
node froga-verify.mjs --packet examples/proof-packet-tampered.json --text   # exit 2, names the failed check
```

Tested on Node 24. No `npm install`; it uses Node built-ins only.

## What it checks (in order; fails closed on the first problem)
1. The packet's own hash.
2. The answer's ledger entry: receipt, input, output and evidence hashes.
3. Inclusion: the entry is in the sealed ledger chain (chain hash, head and length match the seal).
4. The seal's Ed25519 signature. With `--pubkey`, against the key you obtained independently; without it, against the
   key in the packet, and it says so, because a forged packet can carry its own key.
5. Each definition's source file: the embedded bytes hash to the recorded file hash, and the definition's structural
   hash recomputes.
6. Knowledge time: the definition used is the one in effect at the asked date, as known at the asked "known as of" date,
   re-selected by the verifier's own code.
7. Replay (when the data is embedded or passed with `--data`): the verifier recomputes the answer with exact decimal
   arithmetic and must match it exactly.

Exit codes: `0` valid · `2` invalid · `1` unreadable input.

## Two timelines
A metric definition has two times: **when it takes effect** and **when it was recorded**. A correction published on
March 15 but effective March 1 means "March revenue" has two honest answers, depending on what you knew when you asked.
FROGA keeps both, and the verifier checks that the definition used is the right one for both.

## Files
- `froga-verify.mjs`: the verifier (Apache-2.0).
- `docs/receipt-format.md`: the receipt, ledger and proof-packet formats (Apache-2.0).
- `examples/`: a valid packet and a one-digit-tampered copy, on invented demo data.

Format identifiers inside packets read `mantle` (for example `jl.mantle-ledger.v1`). That was the engine's working
name. The identifiers are inside the hashed records, so they stay as they are.

## About
The verifier and format are Apache-2.0. The FROGA engine that produces packets is a separate product by Forseti
Research. This code was written with AI coding agents and checked by a separate validator (a different model, with
sealed tests the builders never saw). Issues and questions are welcome.
