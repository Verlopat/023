#!/usr/bin/env python3
"""One-command entry point: demos, experiments, figures, isolated run folders."""
from __future__ import annotations
import argparse
import asyncio
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
import sys
import time
from rhp.crypto import benchmark_bls
from rhp.evaluation import configure_logging, execute_experiments, new_output_root, write_csv
from rhp.localnet import loopback_roundtrip
from rhp.model import binomial_unsafe, zero_failure_upper_bound
from rhp.primitives import beacon_demo, dispersal_demo, feldman_demo, weak_agreement_demo


def env_value(key: str, default: str) -> str:
    # dotenv-simple: parse .env without executing shell or installing packages.
    content={}
    path=Path('.env')
    if path.exists():
        for raw in path.read_text(encoding='utf-8').splitlines():
            line=raw.strip()
            if not line or line.startswith('#') or '=' not in line: continue
            k,v=line.split('=',1)
            content[k.strip()]=v.strip().strip('"').strip("'")
    return os.environ.get(key,content.get(key,default))


def run(argv=None):
    parser=argparse.ArgumentParser(description='Recursive committee research prototype')
    parser.add_argument('--full',action='store_true',help='100 seeds per config: substantial runtime')
    parser.add_argument('--seed',type=int,default=int(env_value('RHP_SEED','7')))
    parser.add_argument('--beta',type=float,default=float(env_value('RHP_BETA','0.20')))
    parser.add_argument('--loss',type=float,default=float(env_value('RHP_LOSS','0.01')))
    parser.add_argument('--output',default=env_value('RHP_OUTPUT','output'))
    parser.add_argument('--skip-network',action='store_true')
    args=parser.parse_args(argv)
    if not 0 <= args.beta < 1/3: parser.error('beta must be in [0,1/3)')
    if not 0 <= args.loss < 1: parser.error('loss must be in [0,1)')
    out=new_output_root(args.output)
    log=configure_logging(out)
    begin=time.perf_counter()
    log.info('Output directory: %s',out)
    log.info('Research model: no unconditional Byzantine agreement claim')
    try:
        demo={}
        demo['feldman_vss']=feldman_demo()
        seed=sha256(b'RHP:BEACON:DEMO:SEED').digest()
        contributions=[sha256(seed+i.to_bytes(2,'big')).digest() for i in range(5)]
        demo['beacon_commit_reveal']=beacon_demo(seed,contributions)
        demo['vids_erasure_demo']=dispersal_demo()
        demo['weak_agreement_vote']=weak_agreement_demo(['A']*5+['B'])
        demo['bls_multisig']=benchmark_bls()
        if not args.skip_network:
            demo['local_tcp_microtest']=asyncio.run(loopback_roundtrip())
        (out/'results'/'protocol_demos.json').write_text(json.dumps(demo,indent=2),encoding='utf-8')
        bls=demo['bls_multisig']
        write_csv(out/'results'/'crypto_benchmarks.csv',[bls])
        if not bls['available']:
            log.warning('Real BLS not run: install requirements.txt (py_ecc) for BLS benchmark')
        rows,summary=execute_experiments(out,not args.full,args.seed,args.beta,args.loss,log)
        elapsed=time.perf_counter()-begin
        rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        system={'python':sys.version,'platform':platform.platform(),
                'peak_rss_kib_linux':rss,'wall_seconds':elapsed,
                'finished_utc':datetime.now(timezone.utc).isoformat()}
        (out/'results'/'run_environment.json').write_text(json.dumps(system,indent=2),encoding='utf-8')
        (out/'README.txt').write_text('Outputs are scoped to this run. CSV message/byte results are modeled, not measured BLS network traffic.\n'
             'No Byzantine agreement, adaptive security proof, or full DKG protocol is established here.\n',encoding='utf-8')
        log.info('Completed at %s, %.2f seconds',out,elapsed)
        return 0
    except (Exception,KeyboardInterrupt):
        log.exception('Run interrupted; incomplete output remains isolated in %s',out)
        return 1
    finally:
        for h in list(log.handlers):
            h.flush()
            h.close()
            log.removeHandler(h)


if __name__=='__main__':
    raise SystemExit(run())
