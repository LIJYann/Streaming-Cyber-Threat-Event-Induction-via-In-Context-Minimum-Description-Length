#!/usr/bin/env python3
"""Bootstrap uncertainty for the fixed online prediction files.

The resampling unit is a scored document after the shared warm-up window. This
script does not rerun a predictor or alter its state; it quantifies uncertainty
around the already recorded per-document decisions.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from sklearn.metrics import f1_score

LABELS = ["NO_EVENT", "SAME_EVENT", "RELATED_EVENT", "UNSEEN_EVENT"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benchmark", required=True)
    ap.add_argument("--pred", required=True)
    ap.add_argument("--warmup", type=int, default=200)
    ap.add_argument("--samples", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=20260918)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    gold_rows = [json.loads(x) for x in Path(args.benchmark).read_text().splitlines()]
    pred_rows = [json.loads(x) for x in Path(args.pred).read_text().splitlines()]
    if len(gold_rows) != len(pred_rows):
        raise SystemExit("benchmark and prediction lengths differ")
    y = [r["ground_truth_label_name"] for r in gold_rows[args.warmup :]]
    p = [r["label"] for r in pred_rows[args.warmup :]]
    rng = random.Random(args.seed)
    values = {"macro_f1": [], "same_f1": []}
    n = len(y)
    for _ in range(args.samples):
        idx = [rng.randrange(n) for _ in range(n)]
        ys, ps = [y[i] for i in idx], [p[i] for i in idx]
        values["macro_f1"].append(float(f1_score(ys, ps, labels=LABELS, average="macro", zero_division=0)))
        values["same_f1"].append(float(f1_score(ys, ps, labels=["SAME_EVENT"], average="macro", zero_division=0)))
    def ci(xs):
        xs = sorted(xs)
        return {"estimate": sum(xs) / len(xs), "lower_95": xs[int(.025 * len(xs))], "upper_95": xs[int(.975 * len(xs)) - 1]}
    out = {"protocol": {"warmup": args.warmup, "samples": args.samples, "seed": args.seed}, "n_scored": n, "metrics": {k: ci(v) for k, v in values.items()}}
    Path(args.output).write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
