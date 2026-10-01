"""Backups: the textual format, the checksums and share generation.

A backup `#i` holds one point (i, f(i)) of the secret polynomial f. Its 25
words carry 275 bits: the 256-bit scalar f(i), then the 8-bit polynomial
checksum, then the 11-bit words checksum (see "Bit layout").
"""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from secp256k1lab.secp256k1 import GE, Scalar

from .polynomial import evaluate, grind, polynomial_commitment

WORDLIST = (Path(__file__).parent / "bip39_english.txt").read_text().split()
NUM_WORDS = 25


@dataclass(frozen=True)
class Backup:
    """A backup `#index`: the point (index, scalar) and its polynomial checksum."""

    index: int
    scalar: Scalar
    poly_checksum: int


class DecodeError(ValueError):
    """A backup that a decoder must reject."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def polynomial_checksum(index: int, secret_scalar: bytes, F: list[GE]) -> int:
    """Compute the 8-bit checksum binding a backup to the public polynomial F.

    See "Polynomial checksum".
    """
    share_index_32 = index.to_bytes(32, "big")
    commitment = polynomial_commitment(F)
    H = hashlib.sha256(share_index_32 + secret_scalar + commitment).digest()
    return H[0]


def words_checksum(index: int, secret_scalar: bytes, poly_checksum: int) -> int:
    """Compute the 11-bit words checksum, the position of word 25 in the wordlist.

    See "Words checksum".
    """
    share_index_4 = index.to_bytes(4, "big")
    widened = poly_checksum.to_bytes(2, "big")
    H = hashlib.sha256(share_index_4 + secret_scalar + widened).digest()
    return (H[0] << 3) | (H[1] >> 5)


def verify_poly_checksum(backup: Backup, F: list[GE]) -> bool:
    """Check a backup's polynomial checksum against the public polynomial F."""
    expected = polynomial_checksum(backup.index, backup.scalar.to_bytes(), F)
    return backup.poly_checksum == expected


def decode(backup: str) -> Backup:
    """Decode a backup `#<share_index> <word_1> ... <word_25>`.

    See "Textual format", "Bit layout", "Secret scalar" and "Words checksum".
    Raise DecodeError, checking in turn the format, the index, the number of
    words, each word, the scalar and the words checksum.
    """
    parts = backup.split()
    if not parts or re.fullmatch("#[0-9]+", parts[0]) is None:
        raise DecodeError("format", "Invalid format. Expected: #<index> <25 words>")
    index = int(parts[0][1:])
    if index > 0xFFFFFFFF:
        raise DecodeError("index_range", "Share index must fit in 32 bits")
    words = [word.lower() for word in parts[1:]]
    if len(words) != NUM_WORDS:
        raise DecodeError("word_count", f"Expected {NUM_WORDS} words, got {len(words)}")
    bits = 0
    for position, word in enumerate(words, 1):
        if word not in WORDLIST:
            raise DecodeError(
                "unknown_word",
                f"Word #{position} '{word.upper()}' not in BIP39 wordlist",
            )
        bits = (bits << 11) | WORDLIST.index(word)
    scalar, poly_checksum, checksum = bits >> 19, (bits >> 11) & 0xFF, bits & 0x7FF
    if scalar >= Scalar.SIZE:
        raise DecodeError(
            "scalar_range", "Scalar is not less than the secp256k1 group order"
        )
    if words_checksum(index, scalar.to_bytes(32, "big"), poly_checksum) != checksum:
        raise DecodeError(
            "words_checksum", "Words checksum failed. Likely transcription error."
        )
    return Backup(index, Scalar(scalar), poly_checksum)


def encode(backup: Backup) -> str:
    """Encode a backup in canonical form: UPPERCASE, single spaces.

    See "Textual format" and "Bit layout".
    """
    scalar, poly_checksum = backup.scalar, backup.poly_checksum
    checksum = words_checksum(backup.index, scalar.to_bytes(), poly_checksum)
    bits = (int(scalar) << 19) | (poly_checksum << 11) | checksum
    words = [WORDLIST[(bits >> (11 * k)) & 0x7FF] for k in reversed(range(NUM_WORDS))]
    return f"#{backup.index} " + " ".join(words).upper()


def backup_share(index: int, y: Scalar, F: list[GE]) -> Backup:
    """Back up the point (index, y) of a key with public polynomial F.

    See "Share generation". A DKG participant calls this with its own share.
    """
    return Backup(index, y, polynomial_checksum(index, y.to_bytes(), F))


def generate_shares(f: list[Scalar], n: int) -> tuple[list[Backup], list[GE]]:
    """Deal n backups of the secret polynomial f = [s, a_1, ..., a_(t-1)].

    See "Share generation": the coefficients are the caller's choice, the
    fingerprint is ground into them, and share i is f(i) for i = 1..n. A key
    with threshold 1 is backed up as n copies of #0. Return the backups and
    the public polynomial F.
    """
    if not 1 <= len(f) <= n <= 0xFFFFFFFF:
        raise ValueError("Need 1 <= t <= n < 2^32")
    f, F, _ = grind(f)
    if len(f) == 1:
        return [backup_share(0, f[0], F)] * n, F
    return [backup_share(i, evaluate(f, i), F) for i in range(1, n + 1)], F
