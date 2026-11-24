#!/usr/bin/env python3
"""Tests for the reference implementation, against the vectors in ../vectors."""

import json
from collections.abc import Callable
from dataclasses import replace
from itertools import combinations
from pathlib import Path
from typing import Any

from secp256k1_backups import wallet
from secp256k1_backups.backup import (
    Backup,
    DecodeError,
    backup_share,
    decode,
    encode,
    generate_shares,
    verify_poly_checksum,
)
from secp256k1_backups.polynomial import (
    evaluate,
    fingerprint_bits,
    grind,
    interpolate,
    polynomial_commitment,
)
from secp256k1_backups.recovery import (
    RecoveryError,
    find_polynomial,
    reconstruct,
    restore_share,
    verify_together,
)

# Import from secp256k1lab after secp256k1_backups, which puts the vendored copy
# of secp256k1lab on the path.
#
# isort: split
from secp256k1lab.secp256k1 import GE, G, Scalar

VECTORS_DIR = Path(__file__).parent.parent / "vectors"


def load(name: str) -> Any:
    with open(VECTORS_DIR / name) as f:
        return json.load(f)


def scalars(hexes: list[str]) -> list[Scalar]:
    return [Scalar.from_bytes_checked(bytes.fromhex(h)) for h in hexes]


def points(hexes: list[str]) -> list[GE]:
    return [GE.from_bytes_compressed(bytes.fromhex(h)) for h in hexes]


def error_of(fn: Callable[..., object], *args: Any) -> str:
    try:
        fn(*args)
    except (DecodeError, RecoveryError) as e:
        return e.reason
    raise AssertionError("Expected an error")


def test_decode_vectors() -> None:
    vectors = load("decode_vectors.json")
    for case in vectors["validTestCases"]:
        backup = decode(case["backup"])
        assert backup.index == case["index"]
        assert backup.scalar.to_bytes().hex() == case["scalar"]
        assert backup.poly_checksum == case["polyChecksum"]
        assert encode(backup) == case["canonical"]
    for case in vectors["errorTestCases"]:
        assert error_of(decode, case["backup"]) == case["error"]


def check_key(case: dict[str, Any]) -> None:
    t = case["threshold"]
    secret = Scalar.from_bytes_checked(bytes.fromhex(case["secret"]))
    F = points(case["polynomialCommitment"])
    backups = [decode(text) for text in case["backups"]]
    assert [encode(backup) for backup in backups] == case["backups"]

    generated, generated_F = generate_shares(
        scalars(case["secretPolynomial"]), len(backups)
    )
    assert generated == backups
    assert polynomial_commitment(generated_F) == polynomial_commitment(F)
    assert fingerprint_bits(F) == case["fingerprintBits"]
    assert all(verify_poly_checksum(backup, F) for backup in backups)

    if t == 1:
        assert reconstruct(backups) == secret
        return
    found_F, on, off = find_polynomial(backups)
    assert polynomial_commitment(found_F) == polynomial_commitment(F)
    assert on == backups and off == []
    for subset in combinations(backups, t):
        images = [(backup.index, backup.scalar * G) for backup in subset]
        assert polynomial_commitment(interpolate(images)) == polynomial_commitment(F)
        assert reconstruct(list(subset), t) == secret


def test_key_vectors() -> None:
    vectors = load("key_vectors.json")
    for case in vectors["validTestCases"]:
        check_key(case)
    for case in vectors["errorTestCases"]:
        backups = [decode(text) for text in case["backups"]]
        assert error_of(reconstruct, backups) == case["error"]
        if "secretPolynomial" in case:
            f = scalars(case["secretPolynomial"])
            F = [a * G for a in f]
            unground = [backup_share(b.index, evaluate(f, b.index), F) for b in backups]
            assert unground == backups
            assert polynomial_commitment(F) == polynomial_commitment(
                points(case["polynomialCommitment"])
            )
            assert fingerprint_bits(F) is None


def test_grind_vectors() -> None:
    for case in load("grind_vectors.json")["testCases"]:
        f = scalars(case["secretPolynomial"])
        ground, F, k = grind(f)
        assert k == case["increments"]
        assert ground == [a + k_j for a, k_j in zip(f, k)]
        assert polynomial_commitment(F) == polynomial_commitment(
            points(case["polynomialCommitment"])
        )
        assert fingerprint_bits(F) == 36
        backups, _ = generate_shares(ground, len(case["backups"]))
        assert [encode(backup) for backup in backups] == case["backups"]
        assert reconstruct(backups) == f[0]


def test_wallet_vectors() -> None:
    for case in load("wallet_vectors.json")["testCases"]:
        secret = Scalar.from_bytes_checked(bytes.fromhex(case["secret"]))
        assert wallet.xprv(secret) == case["xprv"]
        assert wallet.address(secret, 0, 0) == case["receiveAddress"]
        assert wallet.address(secret, 1, 0) == case["changeAddress"]


def key_backups(comment: str) -> list[Backup]:
    vectors = load("key_vectors.json")["validTestCases"]
    case = next(case for case in vectors if case["comment"].startswith(comment))
    return [decode(text) for text in case["backups"]]


def test_restore_share() -> None:
    two_of_three, three_of_five = key_backups("2-of-3"), key_backups("3-of-5")
    F = verify_together(two_of_three)
    share = two_of_three[0]
    restore_share(share, F)
    assert error_of(restore_share, three_of_five[0], F) == "not_on_polynomial"
    tampered = replace(share, poly_checksum=share.poly_checksum ^ 0xFF)
    assert error_of(restore_share, tampered, F) == "malicious_polynomial"


def test_composed_sets() -> None:
    one_of_one, two_of_three = key_backups("1-of-1"), key_backups("2-of-3")
    three_of_five = key_backups("3-of-5")

    # The 2-of-3 polynomial is found, and the 3-of-5 share #3 is not on it.
    mixed = two_of_three[:2] + three_of_five[2:3]
    F, on, off = find_polynomial(mixed)
    assert len(F) == 2 and on == two_of_three[:2] and off == three_of_five[2:3]
    assert reconstruct(on) == reconstruct(two_of_three)
    assert error_of(reconstruct, mixed) == "not_on_polynomial"

    # Never two backups with the same index in one subset.
    F, on, off = find_polynomial(two_of_three + three_of_five[:1])
    assert on == two_of_three and off == three_of_five[:1]

    # The 2-of-3 polynomial is found first, but the 3-of-5 one has more
    # fingerprint bits, 36 to 18.
    F, on, off = find_polynomial(two_of_three[:2] + three_of_five[:3])
    assert on == three_of_five[:3] and off == two_of_three[:2]

    # Four 3-of-5 shares give a zero A_3, so a stated threshold of 4 fails.
    assert error_of(find_polynomial, three_of_five[:4], 4) == "fingerprint"

    assert error_of(reconstruct, two_of_three[:1]) == "too_few_shares"
    error = error_of(reconstruct, one_of_one + two_of_three[:2])
    assert error == "whole_key_with_shares"


# A made-up #1 whose line through #2 of the 2-of-3 key vector passes the
# fingerprint check, as about one foreign backup in 2^18 does by chance. It is
# not a chance find: its scalar is that #2's scalar less 1021656, found by
# grinding, so most of its words match #2's. Its polynomial checksum was then
# computed against the line, where a chance match would almost always fail it.
CHANCE_MATCH = (
    "#1 CASH TRASH FOIL PREFER BUTTER IDEA BRAVE BITTER ITEM WINK DRIFT SMILE "
    "TOMATO LUNCH OPTION HERO THREE ENGINE BLESS MANAGE HORSE HUNT POST SOUL MANUAL"
)


def test_chance_match() -> None:
    _, real_2, real_3 = key_backups("2-of-3")
    foreign = decode(CHANCE_MATCH)
    line = interpolate([(b.index, b.scalar * G) for b in (foreign, real_2)])
    assert fingerprint_bits(line) == 18 and verify_poly_checksum(foreign, line)
    assert not verify_poly_checksum(real_2, line)

    # The line through the foreign #1 and the real #2 is tried first. The real
    # share's checksum rules it out, and the search goes on to the real key.
    _, on, off = find_polynomial([foreign, real_2, real_3])
    assert on == [real_2, real_3] and off == [foreign]
    _, on, off = find_polynomial([foreign, real_2, real_3], 2)
    assert on == [real_2, real_3] and off == [foreign]
    assert error_of(reconstruct, [foreign, real_2, real_3]) == "not_on_polynomial"

    # With nothing else to find, the checksum failure is what gets reported.
    assert error_of(find_polynomial, [foreign, real_2]) == "poly_checksum"


def main() -> None:
    test_decode_vectors()
    test_key_vectors()
    test_grind_vectors()
    test_wallet_vectors()
    test_restore_share()
    test_composed_sets()
    test_chance_match()
    print("All tests passed")


if __name__ == "__main__":
    main()
