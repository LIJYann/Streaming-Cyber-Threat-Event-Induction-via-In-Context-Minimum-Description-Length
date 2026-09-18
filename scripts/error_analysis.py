#!/usr/bin/env python3
"""Deterministic error analysis for a frozen stream prediction file."""
from __future__ import annotations
import argparse, json
from collections import Counter
from pathlib import Path
LABELS=["NO_EVENT","SAME_EVENT","RELATED_EVENT","UNSEEN_EVENT"]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--benchmark',required=True); ap.add_argument('--pred',required=True); ap.add_argument('--warmup',type=int,default=200); ap.add_argument('--output',required=True); a=ap.parse_args()
    g=[json.loads(x) for x in Path(a.benchmark).read_text().splitlines()][a.warmup:]
    p=[json.loads(x) for x in Path(a.pred).read_text().splitlines()][a.warmup:]
    if len(g)!=len(p): raise SystemExit('length mismatch')
    conf=Counter((x['ground_truth_label_name'],y['label']) for x,y in zip(g,p))
    per={}
    for lab in LABELS:
        tp=conf[(lab,lab)]; fp=sum(conf[(z,lab)] for z in LABELS if z!=lab); fn=sum(conf[(lab,z)] for z in LABELS if z!=lab)
        per[lab]={"support":tp+fn,"precision":round(tp/(tp+fp),4) if tp+fp else 0.0,"recall":round(tp/(tp+fn),4) if tp+fn else 0.0}
    errors=Counter(f"{x['ground_truth_label_name']} -> {y['label']}" for x,y in zip(g,p) if x['ground_truth_label_name']!=y['label'])
    out={"warmup":a.warmup,"n_scored":len(g),"per_class":per,"confusion_matrix":{gl:{pl:conf[(gl,pl)] for pl in LABELS} for gl in LABELS},"errors":errors}
    Path(a.output).write_text(json.dumps(out,indent=2)+'\n'); print(json.dumps(out,indent=2))
if __name__=='__main__': main()
