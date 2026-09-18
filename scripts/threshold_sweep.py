#!/usr/bin/env python3
"""Replay MDL threshold decisions from recorded diagnostics.

This is valid only for a fixed candidate retrieval trace: it changes decision
thresholds without rerunning the language model or using ground-truth fields.
"""
from __future__ import annotations
import argparse, json, subprocess, tempfile
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--diagnostics',required=True); ap.add_argument('--stream',required=True); ap.add_argument('--benchmark',required=True); ap.add_argument('--warmup',type=int,default=200); ap.add_argument('--same',type=float,nargs='+',required=True); ap.add_argument('--related',type=float,default=.02); ap.add_argument('--output',required=True); a=ap.parse_args()
    ds=[json.loads(x) for x in Path(a.diagnostics).read_text().splitlines()]
    out=[]
    for s in a.same:
        pred=[]
        seen=set()
        for d in ds:
            if d['label']=='NO_EVENT': lab='NO_EVENT'; target=None
            elif d['best_delta_r_bits']>=s and d['target'] in seen: lab='SAME_EVENT'; target=d['target']
            elif d['best_delta_r_bits']>=a.related and d['best_similarity']>0: lab='RELATED_EVENT'; target=None
            else: lab='UNSEEN_EVENT'; target=None
            pred.append({'id':d['id'],'label':lab,'target':target})
            seen.add(d['id'])
        with tempfile.NamedTemporaryFile('w',suffix='.jsonl',delete=False) as f:
            for r in pred: f.write(json.dumps(r)+'\n')
            p=f.name
        cmd=['python','scripts/evaluate.py','--stream',a.stream,'--benchmark',a.benchmark,'--pred',p,'--warmup',str(a.warmup)]
        result=json.loads(subprocess.check_output(cmd,text=True)); result['same_threshold']=s; out.append(result); Path(p).unlink(missing_ok=True)
    Path(a.output).write_text(json.dumps({'related_threshold':a.related,'results':out},indent=2)+'\n'); print(json.dumps(out,indent=2))
if __name__=='__main__': main()
