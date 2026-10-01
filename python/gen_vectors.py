#!/usr/bin/env python3
"""Generate the JSON test vectors in ../vectors from fixed inputs."""

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from secp256k1_backups import wallet
from secp256k1_backups.backup import (
    WORDLIST,
    DecodeError,
    backup_share,
    decode,
    encode,
    generate_shares,
    words_checksum,
)
from secp256k1_backups.polynomial import evaluate, fingerprint_bits, grind
from secp256k1_backups.recovery import RecoveryError, reconstruct

# Import from secp256k1lab after secp256k1_backups, which puts the vendored copy
# of secp256k1lab on the path.
#
# isort: split
from secp256k1lab.secp256k1 import GE, G, Scalar

VECTORS_DIR = Path(__file__).parent.parent / "vectors"


def scalars(hexes: list[str]) -> list[Scalar]:
    return [Scalar.from_bytes_checked(bytes.fromhex(h)) for h in hexes]


# The secret polynomials of the BIP's keys, already ground, so grinding leaves
# them unchanged.
KEY_1_OF_1 = scalars(["01" * 32])
KEY_2_OF_3 = scalars(
    [
        "01" * 32,
        "912df63469f079efe2e7dabaef3c05320bf773264cd14022059810815611e0a3",
    ]
)
KEY_3_OF_5 = scalars(
    [
        "deadbeef" * 8,
        "4e6dfb81c2cf45d5d60b5a3f6ef2893172813854021a4a7b84b8ddd24ea47426",
        "1750992385adba061654f2624fa742f2a59f98145617f377ffde852731ff77c1",
    ]
)
KEY_4_OF_4 = scalars(
    [
        "02" * 32,
        "a1f01f71061084bf0ca43ca8dc608c36797b8b35902c44988f40263b163656d3",
        "4e05b6d135e7c4b867e70ed80965cb4a23bc06da960b781bf712a32383656718",
        "31e7bddc21f218ff9304974a10a29aa5fe0a796424ebe425fa83b046431a1647",
    ]
)
# A 2-of-2 key whose polynomial is never ground.
UNGROUND_2_OF_2 = scalars(["03" * 32, "04" * 32])


def hexes(f: list[Scalar]) -> list[str]:
    return [a.to_bytes().hex() for a in f]


def commitment(F: list[GE]) -> list[str]:
    return [A.to_bytes_compressed().hex() for A in F]


def expect_error(fn: Callable[..., object], *args: Any) -> str:
    try:
        fn(*args)
    except (DecodeError, RecoveryError) as e:
        return e.reason
    raise AssertionError("Expected an error")


def flip_poly_checksum(backup: str) -> str:
    """Flip every bit of the polynomial checksum and recompute word 25."""
    b = decode(backup)
    return encode(replace(b, poly_checksum=b.poly_checksum ^ 0xFF))


def out_of_range_backup() -> str:
    """Backup #1 encoding the scalar N, with a polynomial checksum of 0."""
    N = Scalar.SIZE
    bits = (N << 19) | (0 << 11) | words_checksum(1, N.to_bytes(32, "big"), 0)
    words = [WORDLIST[(bits >> (11 * k)) & 0x7FF] for k in reversed(range(25))]
    return "#1 " + " ".join(words).upper()


def key_case(comment: str, f: list[Scalar], n: int) -> dict[str, Any]:
    backups, F = generate_shares(f, n)
    return {
        "comment": comment,
        "threshold": len(f),
        "secret": f[0].to_bytes().hex(),
        "secretPolynomial": hexes(f),
        "polynomialCommitment": commitment(F),
        "fingerprintBits": fingerprint_bits(F),
        "backups": [encode(b) for b in backups],
    }


def error_case(comment: str, backups: list[str], **fields: Any) -> dict[str, Any]:
    decoded = [decode(b) for b in backups]
    return {
        "comment": comment,
        **fields,
        "backups": backups,
        "error": expect_error(reconstruct, decoded),
    }


def key_vectors() -> dict[str, Any]:
    valid = [
        key_case("1-of-1, backed up as #0", KEY_1_OF_1, 1),
        key_case("2-of-3", KEY_2_OF_3, 3),
        key_case("3-of-5", KEY_3_OF_5, 5),
        key_case("4-of-4: only A_1 and A_2 carry fingerprint bits", KEY_4_OF_4, 4),
    ]
    one_of_one, two_of_three = valid[0], valid[1]

    F = [a * G for a in UNGROUND_2_OF_2]
    unground = [backup_share(i, evaluate(UNGROUND_2_OF_2, i), F) for i in (1, 2)]
    errors = [
        error_case(
            "2-of-3 with every bit of #1's polynomial checksum flipped",
            [flip_poly_checksum(two_of_three["backups"][0])]
            + two_of_three["backups"][1:],
            polynomialCommitment=two_of_three["polynomialCommitment"],
        ),
        error_case(
            "1-of-1 with every bit of the #0 polynomial checksum flipped",
            [flip_poly_checksum(one_of_one["backups"][0])],
        ),
        error_case(
            "2-of-2 whose polynomial was never ground: every checksum verifies "
            "but the fingerprint check fails",
            [encode(b) for b in unground],
            secretPolynomial=hexes(UNGROUND_2_OF_2),
            polynomialCommitment=commitment(F),
        ),
    ]
    return {
        "description": [
            "Keys and their backups.",
            "",
            "For each valid test case:",
            "  generate_shares(secretPolynomial, len(backups)) gives the backups",
            "  and polynomialCommitment (secretPolynomial is already ground).",
            "  polynomialCommitment carries fingerprintBits bits of the",
            "  fingerprint, and every backup's polynomial checksum verifies",
            "  against it. Any `threshold` of the backups interpolate it and",
            "  reconstruct `secret`.",
            "",
            "For each error test case:",
            "  reconstruct(backups) fails, and error names the check that failed:",
            "    fingerprint: no group of the shares forms a key.",
            "    poly_checksum: a backup fails its polynomial checksum.",
        ],
        "validTestCases": valid,
        "errorTestCases": errors,
    }


def decode_case(backup: str, comment: str) -> dict[str, Any]:
    b = decode(backup)
    return {
        "comment": comment,
        "backup": backup,
        "index": b.index,
        "scalar": b.scalar.to_bytes().hex(),
        "polyChecksum": b.poly_checksum,
        "canonical": encode(b),
    }


def decode_error_case(backup: str, comment: str) -> dict[str, Any]:
    return {
        "comment": comment,
        "backup": backup,
        "error": expect_error(decode, backup),
    }


def decode_vectors() -> dict[str, Any]:
    backups, F = generate_shares(KEY_2_OF_3, 3)
    share_1 = encode(backups[0])
    words = share_1.split()
    y = evaluate(KEY_2_OF_3, 0xFFFFFFFF)
    largest_index = encode(backup_share(0xFFFFFFFF, y, F))
    return {
        "description": [
            "Decoding backups from their textual format.",
            "",
            "For each valid test case:",
            "  decode(backup) gives index, scalar and polyChecksum, and encoding",
            "  it gives the canonical form.",
            "",
            "For each error test case:",
            "  decode(backup) fails, and error names the check that failed:",
            "    index_range: the index does not fit in 32 bits.",
            "    word_count: there are not 25 words.",
            "    unknown_word: a word is not in the BIP39 wordlist.",
            "    scalar_range: the scalar is not less than the group order.",
            "    words_checksum: the words checksum fails.",
        ],
        "validTestCases": [
            decode_case(share_1.lower(), "2-of-3 share #1 in lowercase"),
            decode_case(largest_index, "2-of-3 share at the largest index, 2^32 - 1"),
        ],
        "errorTestCases": [
            decode_error_case(
                " ".join(words[:-1] + ["ABANDON"]),
                "2-of-3 share #1 with its last word changed to ABANDON",
            ),
            decode_error_case(out_of_range_backup(), "the scalar is N"),
            decode_error_case(" ".join(words[:-1]), "24 words"),
            decode_error_case(" ".join(words + ["ABANDON"]), "26 words"),
            decode_error_case(
                " ".join(words[:1] + ["BITCOIN"] + words[2:]),
                "a word that is not in the wordlist",
            ),
            decode_error_case(
                " ".join(["#4294967296"] + words[1:]), "the index is 2^32"
            ),
        ],
    }


def grind_vectors() -> dict[str, Any]:
    f = [
        Scalar.from_bytes_checked(hashlib.sha256(f"grind a_{j}".encode()).digest())
        for j in range(3)
    ]
    ground, F, k = grind(f)
    backups, _ = generate_shares(ground, 3)
    return {
        "description": [
            "Grinding the frost-v0 fingerprint into a new key.",
            "",
            "For each test case:",
            "  grind(secretPolynomial) adds G to A_j increments[j] times, giving",
            "  polynomialCommitment. The backups are shares of the ground secret",
            "  polynomial, with a_j increased by increments[j].",
        ],
        "testCases": [
            {
                "comment": "3-of-3 with coefficients a_j = SHA256('grind a_<j>')",
                "secretPolynomial": hexes(f),
                "increments": k,
                "polynomialCommitment": commitment(F),
                "backups": [encode(b) for b in backups],
            }
        ],
    }


def wallet_vectors() -> dict[str, Any]:
    secret = KEY_1_OF_1[0]
    return {
        "description": [
            "Bitcoin wallet derivation from the secret.",
            "",
            "For each test case:",
            "  xprv is the root extended private key, and receiveAddress and",
            "  changeAddress are the first addresses of tr(xprv/0/0/0/0/<0;1>/*).",
        ],
        "testCases": [
            {
                "secret": secret.to_bytes().hex(),
                "xprv": wallet.xprv(secret),
                "receiveAddress": wallet.address(secret, 0, 0),
                "changeAddress": wallet.address(secret, 1, 0),
            }
        ],
    }


def write_json(name: str, data: dict[str, Any]) -> None:
    with open(VECTORS_DIR / name, "w") as f:
        json.dump(data, f, indent=4)
        f.write("\n")


if __name__ == "__main__":
    VECTORS_DIR.mkdir(exist_ok=True)
    write_json("decode_vectors.json", decode_vectors())
    write_json("key_vectors.json", key_vectors())
    write_json("wallet_vectors.json", wallet_vectors())
    write_json("grind_vectors.json", grind_vectors())
    print("Generated test vectors successfully")
