"""Optional real BLS12-381 aggregation via py_ecc with proof-of-possession."""
from __future__ import annotations
from hashlib import sha256
from time import perf_counter
import secrets


def benchmark_bls(size:int=5):
    """Sign one domain-separated message, verify registered PoPs and aggregate.

    BLS multi-signatures are NOT a DKG nor a threshold signature construction.
    """
    try:
        from py_ecc.bls import G2ProofOfPossession as bls
        from py_ecc.bls12_381 import curve_order
    except ImportError as e:
        return {'available':False, 'dependency':'py_ecc>=8.0.0',
                'reason':str(e), 'note':'BLS experiment skipped, not simulated as secure'}
    if not 2 <= size <= 32:
        raise ValueError('invalid BLS benchmark size')
    message=sha256(b'RHP:BLS:BENCHMARK:epoch0\0' + b'committee-certificate').digest()
    sks=[secrets.randbelow(curve_order-1)+1 for _ in range(size)]
    start=perf_counter()
    pks=[bls.SkToPk(sk) for sk in sks]
    proofs=[bls.PopProve(sk) for sk in sks]
    pops_valid=all(bls.PopVerify(pk,pop) for pk,pop in zip(pks,proofs))
    pop_ms=(perf_counter()-start)*1000
    start=perf_counter()
    signatures=[bls.Sign(sk,message) for sk in sks]
    sign_ms=(perf_counter()-start)*1000
    start=perf_counter()
    individual_ok=all(bls.Verify(pk,message,sig) for pk,sig in zip(pks,signatures))
    verify_ms=(perf_counter()-start)*1000
    start=perf_counter()
    aggregate=bls.Aggregate(signatures)
    agg_ms=(perf_counter()-start)*1000
    start=perf_counter()
    accepted=pops_valid and individual_ok and bls.FastAggregateVerify(pks,message,aggregate)
    fast_verify_ms=(perf_counter()-start)*1000
    # BLS aggregation has no standalone notion of quorum: verify bitmap and
    # membership commitment separately before accepting a certificate.
    tampered=bls.FastAggregateVerify(pks,sha256(message).digest(),aggregate)
    return {'available':True,'committee_size':size,'aggregate_valid':accepted,
            'tampered_rejected':not tampered, 'pop_verification_ms':pop_ms,
            'sign_ms':sign_ms,'individual_verify_ms':verify_ms,
            'aggregation_ms':agg_ms,'fast_aggregate_verify_ms':fast_verify_ms,
            'aggregate_bytes':len(aggregate),'signer_count':size,
            'scheme':'BLS proof-of-possession multi-signature; not threshold BLS'}
