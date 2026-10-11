"""Deterministic sortition, hierarchy, quorum calculations and soundness checks.

This is a model of authenticated aggregation, not a Byzantine-agreement protocol.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from math import ceil, comb, exp, log, lgamma
import random


def derive_seed(previous: bytes, epoch: int, beacon: bytes) -> bytes:
    if epoch < 0:
        raise ValueError('epoch must be nonnegative')
    return sha256(b'RHP:EPOCH:v1\0' + previous + epoch.to_bytes(8, 'big') + beacon).digest()


def group_seed(seed: bytes, level: int) -> int:
    return int.from_bytes(sha256(b'RHP:SORT:v1\0' + seed + level.to_bytes(4, 'big')).digest(), 'big')


def quorum(size: int) -> int:
    if size < 1:
        raise ValueError('committee must not be empty')
    return (2 * size) // 3 + 1  # strict >2/3, including size divisible by 3


def unsafe_count(size: int) -> int:
    return (size + 2) // 3  # >= 1/3 is unsafe in the selected model


@dataclass(frozen=True)
class Committee:
    level: int
    index: int
    members: tuple[int, ...]
    child_indices: tuple[int, ...]

    @property
    def threshold(self) -> int:
        return quorum(len(self.members))


@dataclass(frozen=True)
class Hierarchy:
    levels: tuple[tuple[Committee, ...], ...]
    size: int
    epoch: int

    @property
    def depth(self) -> int:
        return len(self.levels)

    @property
    def committee_count(self) -> int:
        return sum(map(len, self.levels))


def make_hierarchy(n: int, s: int, seed: bytes, epoch: int = 0) -> Hierarchy:
    """Make a tree of committees of distinct representatives.

    At level 0 every node appears once. A leader represents each child at the
    next level. Parent certificates still require checking child evidence.
    """
    if n < 2 or not 2 <= s <= n:
        raise ValueError('require n >= 2 and 2 <= committee size <= n')
    representatives = list(range(n))
    levels = []
    child = {}
    level = 0
    while True:
        rng = random.Random(group_seed(seed, level))
        rng.shuffle(representatives)
        committees = []
        next_reps = []
        new_child = {}
        for index, start in enumerate(range(0, len(representatives), s)):
            members = tuple(representatives[start:start + s])
            children = tuple(child[m] for m in members) if level > 0 else ()
            committees.append(Committee(level, index, members, children))
            representative = members[0]
            next_reps.append(representative)
            new_child[representative] = index
        levels.append(tuple(committees))
        if len(committees) == 1:
            break
        representatives = next_reps
        child = new_child
        level += 1
    return Hierarchy(tuple(levels), s, epoch)


def unsafe_hypergeom(n: int, byzantine: int, s: int) -> float:
    """Exact hypergeometric tail P[X >= ceil(s/3)] for uniform w/o replacement."""
    if n < 1 or not 0 <= byzantine <= n or not 1 <= s <= n:
        raise ValueError('invalid population or sample')
    first = unsafe_count(s)
    denom = comb(n, s)
    return sum(comb(byzantine, x) * comb(n - byzantine, s - x)
               for x in range(first, min(s, byzantine) + 1)
               if 0 <= s - x <= n - byzantine) / denom


def binomial_unsafe(beta: float, s: int) -> float:
    if not 0 <= beta <= 1 or s < 1:
        raise ValueError('invalid parameters')
    return sum(comb(s, i) * beta**i * (1-beta)**(s-i)
               for i in range(unsafe_count(s), s+1))


def union_bound(n: int, corrupted: int, s: int, committees: int) -> float:
    if committees < 0:
        raise ValueError('invalid committee count')
    return min(1.0, committees * unsafe_hypergeom(n, corrupted, s))


def model_contacts(n: int, s: int) -> float:
    if not 2 <= s <= n:
        raise ValueError('invalid n/s')
    return s * log(n) / log(s)


def zero_failure_upper_bound(trials: int, confidence: float = .95) -> float:
    """One-sided exact binomial confidence upper limit for zero observed failures."""
    if trials < 1 or not 0 < confidence < 1:
        raise ValueError('invalid confidence/trials')
    return 1 - (1 - confidence)**(1/trials)


def wilson_interval(failures: int, trials: int, z: float = 1.95996398454) -> tuple[float,float]:
    if trials < 1 or not 0 <= failures <= trials:
        raise ValueError('invalid failures/trials')
    p = failures / trials
    d = 1 + z*z / trials
    center = (p + z*z/(2*trials))/d
    half = z * ((p*(1-p)/trials + z*z/(4*trials*trials)) ** .5)/d
    return max(0., center-half), min(1., center+half)


def digest_membership(members: tuple[int, ...], epoch: int, level: int) -> bytes:
    payload = b''.join(i.to_bytes(8, 'big') for i in sorted(members))
    return sha256(b'RHP:MEMBERS:v1\0' + epoch.to_bytes(8,'big') + level.to_bytes(4,'big') + payload).digest()


def collect_hierarchy_stats(h: Hierarchy, byzantine: set[int]):
    unsafe = 0
    sizes = []
    participants = {}
    for layer in h.levels:
        for committee in layer:
            bad = sum(i in byzantine for i in committee.members)
            unsafe += bad >= unsafe_count(len(committee.members))
            sizes.append(len(committee.members))
            for node in committee.members:
                participants[node] = participants.get(node, 0) + (len(committee.members) - 1)
    return {
        'unsafe_committees': unsafe,
        'committee_count': len(sizes),
        'min_committee_size': min(sizes),
        'max_committee_size': max(sizes),
        'max_peer_contacts': max(participants.values(), default=0),
        'avg_peer_contacts': sum(participants.values()) / h_size(h),
        'levels': h.depth,
    }


def h_size(h: Hierarchy) -> int:
    return sum(len(c.members) for c in h.levels[0])
