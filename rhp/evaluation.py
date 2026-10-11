"""Experiment orchestration, CSV, plots, JSON configuration and run directories."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import csv
import json
import logging
import os
import statistics
import sys
from .model import wilson_interval, zero_failure_upper_bound, binomial_unsafe
from .simulator import Scenario, run_scenario


def new_output_root(base: str | Path='output') -> Path:
    target=Path(base)
    target.mkdir(parents=True,exist_ok=True)
    for i in range(1,1_000_000):
        path=target/f'test{i}'
        try:
            path.mkdir()
        except FileExistsError:
            continue
        (path/'results').mkdir()
        (path/'plots').mkdir()
        return path
    raise RuntimeError('run directory numbering exhausted')


class JsonFormatter(logging.Formatter):
    def format(self,record):
        return json.dumps({'timestamp':datetime.fromtimestamp(record.created,timezone.utc).isoformat(),
                           'severity':record.levelname,'logger':record.name,
                           'message':record.getMessage()},ensure_ascii=False)


def configure_logging(path:Path):
    log=logging.getLogger('rhp')
    log.setLevel(logging.INFO)
    log.handlers.clear()
    h=logging.FileHandler(path/'run.jsonl',encoding='utf-8')
    h.setFormatter(JsonFormatter())
    log.addHandler(h)
    stream=logging.StreamHandler(sys.stdout)
    stream.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
    log.addHandler(stream)
    return log


def write_csv(path:Path, rows:list[dict]):
    if not rows:
        path.write_text('',encoding='utf-8')
        return
    keys=list(dict.fromkeys(key for row in rows for key in row))
    with path.open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def experiment_grid(quick:bool=True, seed:int=7, beta:float=.20, loss:float=.01):
    n_values=(100,1000) if quick else (100,1000,10000,100000)
    s_values=(8,16,32) if quick else (2,4,8,16,32,64,128,256)
    adversaries=('static_random','adaptive','rushing','static_balanced')
    repetitions=3 if quick else 100
    for n in n_values:
        for s in s_values:
            if s>n: continue
            for adv in adversaries:
                for rep in range(repetitions):
                    yield Scenario(n=n,s=s,beta=beta,adversary=adv,loss=loss,
                                   seed=seed+rep*10007,epoch=rep)


def summaries(rows:list[dict]):
    grouped=defaultdict(list)
    for row in rows:
        grouped[(row['n'],row['s'],row['adversary'])].append(row)
    out=[]
    for (n,s,adversary), group in sorted(grouped.items()):
        count=len(group)
        failures=sum(not row['all_committees_valid_model'] for row in group)
        ci=wilson_interval(failures,count)
        upper=zero_failure_upper_bound(count) if failures==0 else None
        out.append({'n':n,'s':s,'adversary':adversary,'trials':count,
                    'failures':failures,'empirical_failure_rate':failures/count,
                    'wilson_lower_95':ci[0],'wilson_upper_95':ci[1],
                    'zero_failures_one_sided_upper_95':upper,
                    'avg_bytes_per_node_model':statistics.mean(r['bytes_per_node'] for r in group),
                    'avg_messages_per_node_model':statistics.mean(r['messages_per_node'] for r in group),
                    'avg_latency_ms_model':statistics.mean(r['latency_ms_model'] for r in group),
                    'avg_max_contacts':statistics.mean(r['max_peer_contacts'] for r in group),
                    'max_peak_event_queue':max(r['peak_event_queue'] for r in group),
                    'mean_union_bound':statistics.mean(r['uniform_sampling_union_bound'] for r in group)})
    return out


def write_plots(path:Path, data:list[dict], log):
    """Generate research diagnostic PDFs; never silently invent observed metrics."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        log.warning('matplotlib missing: PDF plots skipped; CSV data is retained')
        return False
    regular=[r for r in data if r['adversary']=='static_random']
    specs=[('communication_vs_n','n','avg_bytes_per_node_model','Modeled transmitted bytes per node'),
           ('normalized_complexity','n','avg_messages_per_node_model','Modeled messages per node'),
           ('latency_vs_n','n','avg_latency_ms_model','Modeled latency (ms)'),
           ('failure_probability','n','empirical_failure_rate','Observed failure fraction'),
           ('committee_size_tradeoff','s','avg_max_contacts','Largest peer-contact count'),
           ('memory_vs_n','n','max_peak_event_queue','Peak queued committee events'),
           ('cryptographic_cost','n','avg_messages_per_node_model','Messages per node (NOT measured crypto CPU)')]
    for filename,x_key,y_key,y_label in specs:
        fig,ax=plt.subplots(figsize=(7.0,4.5))
        series=sorted(set(r['s'] for r in regular)) if x_key=='n' else sorted(set(r['n'] for r in regular))
        group_key='s' if x_key=='n' else 'n'
        for value in series:
            points=sorted((r[x_key],r[y_key]) for r in regular if r[group_key]==value)
            if points:
                ax.plot([p[0] for p in points],[p[1] for p in points],marker='o',label=f'{group_key}={value}')
        ax.set_xlabel(x_key)
        ax.set_ylabel(y_label)
        if filename=='normalized_complexity':
            ax.set_ylabel('Modeled messages/node; NOT normalized by complexity curve')
        if filename=='cryptographic_cost':
            ax.set_ylabel('Messages/node proxy; no BLS timing measured')
        ax.grid(alpha=.3)
        ax.legend(fontsize=7)
        fig.tight_layout()
        fig.savefig(path/f'{filename}.pdf')
        plt.close(fig)
    return True


def execute_experiments(run_dir:Path, quick:bool, seed:int, beta:float, loss:float, log):
    rows=[]
    for config in experiment_grid(quick,seed,beta,loss):
        rows.append(run_scenario(config))
    summary=summaries(rows)
    base=run_dir/'results'
    write_csv(base/'communication.csv',rows)
    write_csv(base/'latency.csv',[{k:r[k] for k in ('n','s','adversary','epoch','latency_ms_model','levels')}
                                  for r in rows])
    write_csv(base/'committee_security.csv',[{k:r[k] for k in ('n','s','adversary','epoch','unsafe_committees','committee_count','uniform_sampling_union_bound')}
                                             for r in rows])
    write_csv(base/'failure_rates.csv',summary)
    write_csv(base/'memory.csv',[{k:r[k] for k in ('n','s','adversary','epoch','peak_event_queue')}
                              for r in rows])
    write_csv(base/'crypto_benchmarks.csv',[{'kind':'not_measured','note':'The message-count simulator is not a BLS timing benchmark'}])
    (base/'configurations.json').write_text(json.dumps({'mode':'quick' if quick else 'full',
                              'seed':seed,'beta':beta,'loss':loss,'trial_count':len(rows),
                              'caveats':['Committee certificates and sizes are modeled, not real BLS operations',
                                         'Static sortition union bound inapplicable to adaptively targeted corruption',
                                         'No unconditional BA or lower bound claim']},indent=2),encoding='utf-8')
    write_plots(run_dir/'plots',summary,log)
    log.info('Completed %d simulator trials; %d configuration groups',len(rows),len(summary))
    return rows,summary
