#!/usr/bin/env python3
"""Replay MDL threshold decisions from recorded diagnostics.

This is valid only for a fixed candidate retrieval trace: it changes decision
thresholds without rerunning the language model or using ground-truth fields.
"""
from __future__ import annotations
import argparse, json, subprocess, tempfile
import sys
from pathlib import Path

def replay(ds, same, related):
    if same < related:
        raise ValueError('SAME threshold must be >= RELATED threshold')
    pred=[]
    seen=set()
    for d in ds:
        target=None
        if not d.get('is_event', d['label'] != 'NO_EVENT'):
            lab='NO_EVENT'
        elif d['n_candidates'] > 0 and d['best_delta_r_bits'] >= same:
            target=d.get('best_candidate_id', d['target'])
            if target not in seen:
                raise ValueError(f"{d['id']}: missing earlier best candidate; legacy diagnostics cannot replay this threshold")
            lab='SAME_EVENT'
        elif d['n_candidates'] > 0 and d['best_delta_r_bits'] >= related and d['best_similarity'] > 0:
            lab='RELATED_EVENT'
        else:
            lab='UNSEEN_EVENT'
        pred.append({'id':d['id'],'label':lab,'target':target})
        seen.add(d['id'])
    return pred

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--diagnostics',required=True); ap.add_argument('--stream',required=True); ap.add_argument('--benchmark',required=True); ap.add_argument('--warmup',type=int,default=200); ap.add_argument('--same',type=float,nargs='+',required=True); ap.add_argument('--related',type=float,default=.02); ap.add_argument('--output',required=True); a=ap.parse_args()
    ds=[json.loads(x) for x in Path(a.diagnostics).read_text().splitlines()]
    out=[]
    for s in a.same:
        pred=replay(ds,s,a.related)
        with tempfile.NamedTemporaryFile('w',suffix='.jsonl',delete=False) as f:
            for r in pred: f.write(json.dumps(r)+'\n')
            p=f.name
        cmd=[sys.executable,str(Path(__file__).with_name('evaluate.py')),'--stream',a.stream,'--benchmark',a.benchmark,'--pred',p,'--warmup',str(a.warmup)]
        try:
            result=json.loads(subprocess.check_output(cmd,text=True))
        finally:
            Path(p).unlink(missing_ok=True)
        result['predictor']='fixed_trace_mdl'; result['same_threshold']=s; out.append(result)
    Path(a.output).write_text(json.dumps({'related_threshold':a.related,'results':out},indent=2)+'\n'); print(json.dumps(out,indent=2))
if __name__=='__main__': main()
