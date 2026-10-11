"""Bounded-memory, committee-event simulator and adversarial experiment harness.

Messages/bytes are explicitly modeled sizes, not measured socket payloads.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from hashlib import sha256
from heapq import heappush, heappop
from math import ceil
import random
import time
import tracemalloc
from .model import derive_seed, make_hierarchy, quorum, unsafe_count, collect_hierarchy_stats, union_bound, model_contacts


@dataclass(frozen=True)
class Scenario:
    n: int
    s: int
    beta: float = .20
    adversary: str = 'static_random'
    loss: float = .01
    delay_ms: float = 30.0
    jitter_ms: float = 8.0
    crypto_us: float = 35.0
    seed: int = 17
    epoch: int = 0

    def validate(self):
        if not (2 <= self.s <= self.n <= 1_000_000):
            raise ValueError('require 2 <= s <= n <= 1e6')
        if not (0 <= self.beta < 1/3):
            raise ValueError('beta must be >=0 and strictly <1/3')
        if self.adversary not in {'static_random','static_balanced','adaptive','rushing'}:
            raise ValueError('unknown adversary')
        if not 0 <= self.loss < 1 or min(self.delay_ms,self.jitter_ms,self.crypto_us) < 0:
            raise ValueError('invalid loss/delay/crypto')


def corrupted_nodes(s: Scenario, hierarchy, rng: random.Random) -> set[int]:
    budget = int(s.beta * s.n)
    if not budget:
        return set()
    if s.adversary == 'static_random' or s.adversary == 'rushing':
        return set(rng.sample(range(s.n), budget))
    if s.adversary == 'static_balanced':
        # Fixed evenly distributed identifiers; chosen independently of sortition.
        return {(i * s.n) // budget for i in range(budget)}
    # Adaptive attacker sees assignment and can allocate its global corruption
    # budget to targeted root / smaller committees. This is not hidden sortition.
    priority = [node for layer in reversed(hierarchy.levels)
                for c in sorted(layer,key=lambda x:len(x.members)) for node in c.members]
    selected = set()
    for node in priority:
        selected.add(node)
        if len(selected) == budget: break
    return selected


def run_scenario(s: Scenario) -> dict:
    s.validate()
    start = time.perf_counter()
    rng = random.Random(s.seed + s.epoch * 991)
    initial = sha256(f'RHP:SEED:{s.seed}'.encode()).digest()
    derived = derive_seed(initial, s.epoch, sha256(str(s.seed).encode()).digest())
    h = make_hierarchy(s.n,s.s,derived,s.epoch)
    corrupted = corrupted_nodes(s,h,rng)
    stat = collect_hierarchy_stats(h,corrupted)
    # Each committee event signals local verification completion; parent only
    # starts after child certificates are considered. At any time, the scheduler
    # stores only events from the current level.
    child_valid = {}
    child_times = {}
    messages = 0
    bytes_total = 0
    certificate_bytes = 0
    crypto_ops = 0
    events = 0
    peak_queue = 0
    epoch_success = True
    for level, layer in enumerate(h.levels):
        event_queue=[]
        pending={}
        for committee in layer:
            valid_children = (sum(bool(child_valid.get(idx)) for idx in committee.child_indices)
                              if level else len(committee.members))
            bad = sum(node in corrupted for node in committee.members)
            honest = len(committee.members)-bad
            # A rushing adversary withholds all its contributions. The remaining
            # scenarios also conservatively assume Byzantine nodes do not help.
            received = sum(rng.random() >= s.loss for _ in range(honest))
            enough_members = received >= committee.threshold
            enough_children = (valid_children >= quorum(len(committee.child_indices))
                               if level else True)
            good = enough_members and enough_children
            child_start=max((child_times.get(idx,0.) for idx in committee.child_indices), default=0.)
            # Delivery event is modeled, not one event per packet.
            duration=max(0.,rng.gauss(s.delay_ms,s.jitter_ms)) + received*s.crypto_us/1000
            finish=child_start+duration
            heappush(event_queue,(finish,committee.index,good))
            pending[committee.index]=committee
            crypto_ops+=received
            # One contribution broadcast from each honest node to peers.
            # Includes failed / lost transmissions in the on-wire cost.
            local_msgs = honest * (len(committee.members)-1)
            messages+=local_msgs
            bytes_total+=local_msgs*(96+32+64)  # BLS signature, ID / framing model
            # Compact modeled cert: BLS aggregate + bitset + membership hash
            # + digest per child. Child evidence itself is NOT magically proved.
            size=96 + ceil(len(committee.members)/8)+32+32*len(committee.child_indices)
            certificate_bytes+=size
            if level:
                messages+=len(committee.child_indices)
                bytes_total+=size*len(committee.child_indices)
        peak_queue=max(peak_queue,len(event_queue))
        valid={}
        times={}
        while event_queue:
            finish,idx,good=heappop(event_queue)
            valid[idx]=good
            times[idx]=finish
            events+=1
        child_valid,child_times=valid,times
        epoch_success=epoch_success and all(valid.values())
    duration_ms=max(child_times.values(),default=0.)
    # One failed committee is considered global failure for this strong model.
    root_valid=bool(child_valid.get(0))
    elapsed_ms=(time.perf_counter()-start)*1000
    return {
        **asdict(s), **stat,
        'corrupted_count':len(corrupted),
        'root_certificate_valid_model':root_valid,
        'all_committees_valid_model':epoch_success,
        'messages':messages,
        'messages_per_node':messages/s.n,
        'bytes':bytes_total,
        'bytes_per_node':bytes_total/s.n,
        'certificate_bytes_model':certificate_bytes,
        'latency_ms_model':duration_ms,
        'crypto_verifications_model':crypto_ops,
        'events_processed':events,
        'peak_event_queue':peak_queue,
        'wall_time_ms':elapsed_ms,
        'peer_contact_bound_sk_model':s.s*h.depth,
        'symbolic_s_log_n_log_s':model_contacts(s.n,s.s),
        'uniform_sampling_union_bound':union_bound(s.n,int(s.beta*s.n),s.s,h.committee_count),
        'measurement_kind':'simulation (not real network or BLS microbenchmark)',
    }
