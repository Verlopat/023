"""Pedagogical Feldman VSS, erasure dispersal, and weak-agreement demonstrators.

These modules are deliberately NOT described as production-grade threshold DKG,
BLS threshold beacons, consensus, or complete VIDS protocols.
"""
from __future__ import annotations
from hashlib import sha256
from hmac import compare_digest
import secrets
from .model import quorum

# RFC 3526 MODP group 5 1536-bit safe prime (demo only); 4 has order q.
P = int('''FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
 EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
 EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
 C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
 670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF'''.replace(' ','').replace('\n',''),16)
Q = (P-1)//2
G = 4


def polynomial(coefficients: list[int], x: int, field: int = Q) -> int:
    total = 0
    for a in reversed(coefficients):
        total = (total * x + a) % field
    return total


def verify_share(share: int, x: int, commitments: list[int]) -> bool:
    rhs, power = 1, 1
    for commitment in commitments:
        rhs = (rhs * pow(commitment, power, P)) % P
        power = (power * x) % Q
    return pow(G, share, P) == rhs


def lagrange_at_zero(points: list[tuple[int, int]], field: int = Q) -> int:
    result = 0
    if len({x for x, _ in points}) != len(points):
        raise ValueError('duplicate interpolation coordinates')
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = num * (-xj) % field
                den = den * (xi - xj) % field
        result = (result + yi * num * pow(den, -1, field)) % field
    return result


def feldman_demo(participants: int = 5, threshold: int = 3):
    if not 2 <= threshold <= participants < 100:
        raise ValueError('invalid threshold')
    dealers = []
    for _ in range(participants):
        coeffs = [secrets.randbelow(Q) for _ in range(threshold)]
        commitments = [pow(G, a, P) for a in coeffs]
        shares = [polynomial(coeffs, x) for x in range(1, participants+1)]
        assert all(verify_share(shares[x-1], x, commitments) for x in range(1, participants+1))
        dealers.append((commitments, shares))
    combined = [sum(d[1][x] for d in dealers) % Q for x in range(participants)]
    public = 1
    for commitments, _ in dealers:
        public = public * commitments[0] % P
    recovered = lagrange_at_zero([(i+1, combined[i]) for i in range(threshold)])
    return {'participants': participants, 'threshold': threshold,
            'valid_shares': participants * participants,
            'reconstruction_matches_public': pow(G, recovered, P) == public,
            'scheme': 'Feldman VSS demonstration; not full adversarial DKG'}


def beacon_demo(seed: bytes, contributions: list[bytes], dropped: set[int] | None = None):
    """Commit-reveal hash beacon; exposes selective-withholding risk."""
    dropped = dropped or set()
    commitments = [sha256(b'RHP:COMMIT\0' + c).digest() for c in contributions]
    available = [(i,c) for i,c in enumerate(contributions) if i not in dropped]
    if len(available) < quorum(len(contributions)):
        return {'available': False, 'reason': 'insufficient reveals'}
    if not all(compare_digest(sha256(b'RHP:COMMIT\0' + c).digest(), commitments[i])
               for i, c in available):
        return {'available': False, 'reason': 'invalid reveal'}
    digest = sha256(b'RHP:BEACON:DEMO\0' + seed + b''.join(i.to_bytes(4,'big')+c for i,c in available)).hexdigest()
    return {'available': True, 'value': digest, 'reveals': len(available),
            'warning': 'selective abort may bias output; not an unbiasable threshold beacon'}


def _merkle_parent(left: bytes, right: bytes) -> bytes:
    return sha256(b'RHP:MERKLE:NODE\0' + left + right).digest()


def merkle_leaf(index: int, data: int) -> bytes:
    return sha256(b'RHP:MERKLE:LEAF\0' + index.to_bytes(4,'big') + data.to_bytes(32,'big')).digest()


def merkle_tree(values: list[int]):
    nodes = [merkle_leaf(i, value) for i, value in enumerate(values)]
    levels = [nodes]
    while len(nodes)>1:
        if len(nodes)%2:
            nodes=nodes+[nodes[-1]]
        nodes=[_merkle_parent(nodes[i], nodes[i+1]) for i in range(0,len(nodes),2)]
        levels.append(nodes)
    return levels


def merkle_proof(levels: list[list[bytes]], index: int):
    proof=[]
    for nodes in levels[:-1]:
        sibling = index ^ 1
        proof.append(nodes[sibling if sibling < len(nodes) else index])
        index//=2
    return proof


def merkle_verify(root: bytes, index: int, value: int, proof: list[bytes]):
    digest=merkle_leaf(index,value)
    for sibling in proof:
        digest=_merkle_parent(digest,sibling) if index%2==0 else _merkle_parent(sibling,digest)
        index//=2
    return compare_digest(digest,root)


def dispersal_demo(message: bytes = b'Byzantine data availability', n: int = 9, k: int = 5):
    """Polynomial erasure dispersal over field Q with Merkle-authenticated shards.

    This models erasure/recovery, not asynchronous availability or agreement.
    """
    if not 2 <= k <= n <= 64 or len(message) > 30*k:
        raise ValueError('invalid dispersal dimensions/payload')
    coefficients = [int.from_bytes(message[i:i+30], 'big') for i in range(0, len(message),30)]
    coefficients.extend([0]*(k-len(coefficients)))
    shards = [polynomial(coefficients, x) for x in range(1, n+1)]
    tree = merkle_tree(shards)
    root = tree[-1][0]
    valid = all(merkle_verify(root, j, shards[j], merkle_proof(tree,j)) for j in range(n))
    # Reconstruct polynomial via interpolation evaluated at k points; verify against shards.
    def interpolate(x):
        total=0
        for i in range(k):
            xi=i+1
            basis=1
            for j in range(k):
                if i!=j:
                    basis=basis*(x-(j+1))*pow(xi-(j+1),-1,Q)%Q
            total=(total+shards[i]*basis)%Q
        return total
    consistent=all(interpolate(i+1)==shards[i] for i in range(n))
    # Original coefficients are recovered by evaluating finite differences / Vandermonde solve.
    matrix=[[pow(i+1,j,Q) for j in range(k)]+[shards[i]] for i in range(k)]
    for col in range(k):
        pivot=next(row for row in range(col,k) if matrix[row][col] % Q)
        matrix[col],matrix[pivot]=matrix[pivot],matrix[col]
        factor=pow(matrix[col][col],-1,Q)
        matrix[col]=[(v*factor)%Q for v in matrix[col]]
        for row in range(k):
            if row==col: continue
            factor=matrix[row][col]
            matrix[row]=[(a-factor*b)%Q for a,b in zip(matrix[row],matrix[col])]
    reconstructed=b''.join(int(matrix[j][-1]).to_bytes(30,'big')[-len(message[j*30:(j+1)*30]):] for j in range(k) if message[j*30:(j+1)*30])
    return {'n':n, 'k':k, 'merkle_valid':valid, 'shards_consistent':consistent,
            'message_recovered': reconstructed == message, 'merkle_root':root.hex(),
            'scheme':'Authenticated polynomial erasure coding demo; not a complete VIDS protocol'}


def weak_agreement_demo(votes: list[str], faulty: set[int] | None = None):
    """Single-round certified vote; does not guarantee termination/Byzantine agreement."""
    if not votes: raise ValueError('votes cannot be empty')
    faulty=faulty or set()
    valid=[v for i,v in enumerate(votes) if i not in faulty]
    counts={v:valid.count(v) for v in set(valid)}
    required=quorum(len(votes))
    candidates=sorted(v for v,count in counts.items() if count>=required)
    return {'certified_value':candidates[0] if candidates else None,
            'quorum':required,'honest_votes':len(valid),'agreement_proven':False}
