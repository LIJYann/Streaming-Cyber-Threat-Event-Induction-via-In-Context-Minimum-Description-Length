# CCF debate record — ICLR 2027

Benchmark: https://github.com/LIJYann/Streaming-Cyber-Threat-Event-Induction-via-In-Context-Minimum-Description-Length

## Astra — idea refinement

CTI event discovery is usually offline clustering or entity matching, while a stateful open-world stream must distinguish SAME, RELATED, UNSEEN, and NO_EVENT as memory changes. The gap is a reproducible online protocol that evaluates both step decisions and the final event partition. The proposed method treats a frozen language model as a conditional encoder and compares token-normalized code length with and without incident/campaign context. The falsifiable claim is that this conditional compression improves SAME-vs-RELATED attribution and B-cubed F1 on the no-title stream; it must be rejected if a matched entity baseline removes the gain. “Causal reasoning” and superiority to GPT-4o remain unverified claims.

## Sol — planning and gates

The work is staged as: repair and benchmark generation; test and reproducibility gates; freeze and byte-level replay; solvability audit; warm-up/Macro-F1/B-cubed/ARI evaluation; then manuscript synchronization. The current gates are 60 passing tests, exact synthetic 250/250/250/250 counts, frozen SHA-256 replay, and a documented no-title limitation. No new feeds or cross-vendor crawling are allowed. Every paper number must come from a rerunnable script.

## Luna — code and writing

The benchmark now includes network-traffic and endpoint-forensics views for synthetic parallel reports, bounded title generation, a solvability audit, and a standard evaluation CLI. The README records the protocol and the observed unanchored rates in Real-Augmented/notitle (SAME 43.0%, RELATED 16.6%). The implementation is frozen only after `pytest`, `build_all.py check`, and the SHA-256 lock all pass.

## Debate resolution

Use `notitle` as the main projection, retain `with_title` only as an upper-bound diagnostic, and report the real-data information limitation rather than imputing missing context. The next scientific test is a controlled comparison against lexical, entity, and embedding baselines under the same warm-up and candidate budget.
