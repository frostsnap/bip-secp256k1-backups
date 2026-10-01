"""The secret polynomial f and the public polynomial F = f·G.

Coefficients are listed constant term first: f = [a_0, ..., a_(t-1)] and
F = [A_0, ..., A_(t-1)] with A_j = a_j·G.
"""

import hashlib

from secp256k1lab.secp256k1 import GE, G, Scalar

TAG = b"frost-v0"
BITS_PER_COEFF = 18
MAX_BITS_TOTAL = 36


def evaluate(f: list[Scalar], x: int) -> Scalar:
    """Evaluate the secret polynomial f at x."""
    y = Scalar(0)
    for a in reversed(f):
        y = y * x + a
    return y


def evaluate_public(F: list[GE], x: int) -> GE:
    """Evaluate the public polynomial F at x, giving the public image f(x)·G."""
    image: GE = GE.batch_mul(*((Scalar(x) ** j, A) for j, A in enumerate(F)))
    return image


def lagrange_basis(x_i: int, xs: list[int]) -> list[Scalar]:
    """Return the coefficients of L_i(x) = Π_{j≠i} (x - x_j) / (x_i - x_j)."""
    basis = [Scalar(1)]
    for x_j in xs:
        if x_j != x_i:
            times_x = [Scalar(0)] + basis
            times_x_j = [b * x_j for b in basis] + [Scalar(0)]
            basis = [(p - q) / (x_i - x_j) for p, q in zip(times_x, times_x_j)]
    return basis


def interpolate(images: list[tuple[int, GE]]) -> list[GE]:
    """Interpolate the public polynomial F from t public images (x_i, y_i·G).

    The indices x_i must be distinct. See "Verifying backups together", step 1.
    """
    xs = [x for x, _ in images]
    bases = [lagrange_basis(x, xs) for x in xs]
    return [
        GE.batch_mul(*((basis[j], Y) for basis, (_, Y) in zip(bases, images)))
        for j in range(len(images))
    ]


def ser(A: GE) -> bytes:
    """Serialize a point in 33-byte compressed form.

    The BIP defines no serialization for the point at infinity, so it is
    rejected.
    """
    if A.infinity:
        raise ValueError("The point at infinity has no serialization")
    data: bytes = A.to_bytes_compressed()
    return data


def polynomial_commitment(F: list[GE]) -> bytes:
    """Return ser(A_0) || ... || ser(A_(t-1)). See "Polynomial checksum"."""
    return b"".join(ser(A) for A in F)


def leading_zero_bits(digest: bytes) -> int:
    """Count the zero bits at the start of a digest, most significant first."""
    return 8 * len(digest) - int.from_bytes(digest, "big").bit_length()


def fingerprint_bits(F: list[GE]) -> int | None:
    """Check that F carries the frost-v0 fingerprint. See "Fingerprint".

    Return the number of fingerprint bits checked, or None if the check fails.
    A polynomial with t = 1 has no coefficient to check and passes with 0 bits.
    """
    # The running hash state is kept as the bytes it has absorbed so far.
    absorbed = bytes([len(TAG)]) + TAG + ser(F[0])
    bits = 0
    for A in F[1:]:
        needed = min(BITS_PER_COEFF, MAX_BITS_TOTAL - bits)
        if needed == 0:
            break
        if leading_zero_bits(hashlib.sha256(absorbed + ser(A)).digest()) < needed:
            return None
        absorbed += ser(A)
        bits += needed
    return bits


def grind(f: list[Scalar]) -> tuple[list[Scalar], list[GE], list[int]]:
    """Grind the frost-v0 fingerprint into the polynomial f. See "Fingerprint".

    Return the tweaked secret polynomial, its public polynomial F and the
    increments k_j, the number of times G was added to A_j. The constant term
    is never tweaked, so k_0 = 0.
    """
    F = [a * G for a in f]
    k = [0] * len(f)
    absorbed = bytes([len(TAG)]) + TAG + ser(F[0])
    bits = 0
    for j in range(1, len(F)):
        needed = min(BITS_PER_COEFF, MAX_BITS_TOTAL - bits)
        if needed == 0:
            break
        while leading_zero_bits(hashlib.sha256(absorbed + ser(F[j])).digest()) < needed:
            F[j] = F[j] + G
            k[j] += 1
        absorbed += ser(F[j])
        bits += needed
    return [a + k_j for a, k_j in zip(f, k)], F, k
