# Recursive Hierarchical Partitioning for Byzantine Primitives — Research Prototype

A reproducible **research model** of recursively partitioned committees, static/adaptive Byzantine corruptions, and authenticated-aggregation building blocks.

**Scope warning:** This repository does **not** implement or prove secure Byzantine agreement, full adversarial DKG, unbiasable threshold beacons, or a universal matching communication lower bound. Simulated BLS-size estimates are not measured network bytes. The attached paper/research proposal is intentionally **not** included in this repository.

## Requirements and one-command quick start (Ubuntu Linux)

```bash
python3 --version
python3 -m pip --version  # only for optional plotting/real BLS
git --version
git clone https://github.com/Verlopat/023.git
cd 023
python3 Main.py
```

Runs with Python 3.10+ and the standard library. Every invocation creates a new `output/test1`, `output/test2`, ... even if an experiment fails.

### Optional real BLS12-381 and publication-style PDF figures

For Ubuntu's externally-managed system Python, use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 Main.py
```

When `py_ecc` is installed, the entry point additionally performs real BLS12-381 proof-of-possession (PoP) aggregation, individual and fast-aggregate verification, and records timing. **BLS multi-signatures are not threshold signatures.** Without `py_ecc`, the BLS microbenchmark is explicitly marked unavailable, not fabricated. When `matplotlib` is available, seven model diagnostic PDF plots are produced. Missing extras never stop the standard-library simulation.

## Full experiments and tests

```bash
python3 Main.py --full                 # 100 trials per (n, s, adversary) configuration
python3 Main.py --seed 123 --beta 0.20 --loss 0.01
python3 Main.py --skip-network
python3 -m unittest discover -s tests -v
```

Full experiment grid: `n ∈ {100, 1000, 10000, 100000}`, `s ∈ {2,4,8,16,32,64,128,256}` with `s ≤ n`, four adversary models, 100 epochs/seeds. Full runs can be computationally expensive. Quick mode: `n={100,1000}`, `s={8,16,32}`, four adversaries, three trials each. Parameters can also be set in `.env` (see `.env.example`).

## Implemented research components

- **Random sortition and epoch re-derivation:** SHA-256 domain-separated, seeded deterministic committee membership and auditable hierarchy. Public membership is assumed. Adaptive adversaries can therefore target revealed committees.
- **Hierarchy:** representatives advance to parent layers, strict `>2/3` member quorum, and child-certificate validity dependencies. Unbalanced tail committees can be small; inspect `min_committee_size` and do not infer uniform committee safety.
- **Simulation:** bounded per-level heap of committee completion events, modeled traffic bytes/headers, delay, loss, verification operations, peak queue, four strategies (`static_random`, `static_balanced`, `adaptive`, `rushing`). The rushing adversary has limited modeled behavior and is not a formal rushing-security experiment.
- **Probability:** hypergeometric exact unsafe-tail for sampling without replacement; binomial tail utility, union-bound diagnostic, Wilson 95% failure intervals and exact one-sided upper bound for zero observed failures. Static-uniform bounds do **not** apply to adaptive targeting.
- **Feldman verifiable secret sharing demo:** public polynomial commitments, share checking, Lagrange interpolation. Not a production DKG protocol, complaint handling or proactive resharing.
- **Beacon demonstration:** commitment and reveal, explicit warning that selective abort allows bias. Not an unbiased beacon.
- **Information dispersal:** polynomial erasure reconstruction plus Merkle-authenticated shares, without Byzantine recovery/agreement guarantee.
- **Weak agreement:** quorum-certified single-round vote model, not Byzantine consensus.
- **Real BLS12-381:** optional `py_ecc` PoP multi-signature benchmark with tampering tests, not threshold BLS.
- **TCP:** asyncio loopback socket micro-test, not a geographically distributed deployment.

## Outputs

```
output/testN/
  run.jsonl
  README.txt
  results/
    configurations.json
    communication.csv
    latency.csv
    committee_security.csv
    failure_rates.csv
    crypto_benchmarks.csv
    memory.csv
    protocol_demos.json
    run_environment.json
  plots/
    communication_vs_n.pdf        # matplotlib optional
    normalized_complexity.pdf
    latency_vs_n.pdf
    failure_probability.pdf
    committee_size_tradeoff.pdf
    cryptographic_cost.pdf
    memory_vs_n.pdf
```

CSV records are tagged `_model` when generated from symbolic parameters. `run_environment.json` records real execution wall time and peak process RSS on Linux. The crypto benchmark CSV gives real timings only if `py_ecc` can be imported. The figure named `cryptographic_cost.pdf` is an explicitly labeled **message proxy**, not measured BLS CPU time; use the measured benchmark CSV for that.

## Theoretical assumptions and non-results

For nodes `n`, committee size `s` and depth `k≈log_s(n)`, the **symbolic peer-contact model** assumes `O(s)` work per node per level, leading to `O(s log(n)/log(s))` and `O(log² n/log log n)` for `s=Θ(log n)` only **under the stated architecture assumptions**. The simulator tracks peer contacts and aggregate transmission separately; its measured data need not follow that idealized curve. It does not establish that all root certificates are cryptographically self-contained without carrying/verifying underlying child evidence.

**Important sampling caveat:** the fraction must be *strictly* below 1/3 by a constant gap for exponential tails with a useful constant. At exactly β=1/3, the probability of exceeding the 1/3 unsafe threshold is not negligible. To claim global failure ≤n⁻ᵈ over M=nᶜ uniformly sampled committees, the constant in s=c' log n must account for the gap, c, d and network assumptions; `s=32` is **not** automatically secure at `n=100000`.

**Remaining work for a full research claim:** proof-carrying recursive certificates, authenticated quorum-intersection proofs, stronger anti-adaptive sortition (private eligibility or corruption delay), proper threshold BLS/DKG with complaints, unbiasable beacon, real asynchronous VIDS, validated rushing behavior, multi-process protocol deployment, byte-level empirical benchmarks and formal protocol-model definitions. No theorem of all these properties is claimed by the present code.

## Repository layout

```
Main.py                 # entry point
rhp/model.py            # sortition, hierarchy, probability
rhp/simulator.py        # seeded scenarios and adversaries
rhp/primitives.py       # VSS, beacon, dispersal, vote demonstrators
rhp/crypto.py           # optional real BLS multsig benchmark
rhp/localnet.py         # real TCP loopback micro-test
rhp/evaluation.py       # reproducible experiments, outputs, plots
rhp/__init__.py
tests/test_project.py   # unittest regression suite
```

Only implementation, test, and configuration files are version-controlled. Experimental outputs and `.env` are ignored. No `paper/`, proposal document, bibliography, or paper manuscript is committed.
