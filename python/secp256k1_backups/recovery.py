"""Recovery: verifying backups together, restoring a share and reconstruction."""

from itertools import combinations, product

from secp256k1lab.secp256k1 import GE, G, Scalar

from .backup import Backup, verify_poly_checksum
from .polynomial import MAX_BITS_TOTAL, evaluate_public, fingerprint_bits, interpolate


class RecoveryError(ValueError):
    """A set of backups, or a polynomial, that recovery must reject."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class NotOnPolynomialError(RecoveryError):
    """The share is not on the polynomial. The user can try again."""


class MaliciousPolynomialError(RecoveryError):
    """The share is on the polynomial but its polynomial checksum fails.

    The polynomial's source must be treated as malicious: warn the user, and
    do not retry with a different polynomial.
    """


def _names(backups: list[Backup]) -> str:
    return ", ".join(f"#{backup.index}" for backup in backups)


def find_polynomial(
    backups: list[Backup], t: int | None = None
) -> tuple[list[GE], list[Backup], list[Backup]]:
    """Search the share backups for their public polynomial F.

    See "Verifying backups together". Subsets of t backups are tried, or of
    2, 3, ... backups when t is not known, never with two backups at the same
    index. The first F with the most fingerprint bits is kept, and the search
    stops early at MAX_BITS_TOTAL. Every backup on F must pass its polynomial
    checksum. Return F, the backups that lie on it and those that do not.
    """
    if any(backup.index == 0 for backup in backups):
        raise RecoveryError(
            "whole_key_with_shares", "A #0 backup must not be combined with shares"
        )
    if t is not None and t < 2:
        raise ValueError("A key with threshold 1 is backed up as #0, not as shares")
    by_index: dict[int, list[Backup]] = {}
    for backup in backups:
        by_index.setdefault(backup.index, []).append(backup)
    indices = sorted(by_index)
    min_size = 2 if t is None else t
    if len(indices) < min_size:
        raise RecoveryError(
            "too_few_shares",
            f"Need at least {min_size} shares with different indices, got {len(indices)}",
        )

    sizes = range(2, len(indices) + 1) if t is None else [t]
    subsets = (
        subset
        for size in sizes
        for chosen in combinations(indices, size)
        for subset in product(*(by_index[i] for i in chosen))
    )
    best: tuple[int, list[GE]] | None = None
    for subset in subsets:
        F = interpolate([(backup.index, backup.scalar * G) for backup in subset])
        # A zero top coefficient means the subset fits a smaller threshold. No
        # coefficient may be zero, as the point at infinity has no serialization.
        if any(A.infinity for A in F):
            continue
        bits = fingerprint_bits(F)
        if bits is not None and (best is None or bits > best[0]):
            best = (bits, F)
            if bits == MAX_BITS_TOTAL:
                break
    if best is None:
        if t is None:
            raise RecoveryError(
                "fingerprint",
                "Fingerprint check failed: no group of these shares forms a key. "
                "Fewer shares than the threshold may have been given, or a share "
                "is from a different key or was mistranscribed.",
            )
        raise RecoveryError(
            "fingerprint",
            f"Fingerprint check failed: no {t} of these shares form a key with "
            f"threshold {t}. The threshold may be wrong, or a share is from a "
            "different key or was mistranscribed.",
        )

    F = best[1]
    on_F = [evaluate_public(F, backup.index) == backup.scalar * G for backup in backups]
    on = [backup for backup, ok in zip(backups, on_F) if ok]
    off = [backup for backup, ok in zip(backups, on_F) if not ok]
    failed = [backup for backup in on if not verify_poly_checksum(backup, F)]
    if failed:
        raise RecoveryError(
            "poly_checksum",
            f"Polynomial checksum failed for share {_names(failed)}. A share may be "
            "from a different key or mistranscribed, or fewer shares than the "
            "threshold were given.",
        )
    return F, on, off


def verify_together(backups: list[Backup], t: int | None = None) -> list[GE]:
    """Verify share backups against their public polynomial F, and return F.

    See "Verifying backups together": F is found as in find_polynomial, and
    the set is rejected unless every backup lies on it.
    """
    F, _, off = find_polynomial(backups, t)
    if off:
        raise RecoveryError(
            "not_on_polynomial",
            f"These shares do not lie on the polynomial: {_names(off)}. Each is from "
            "a different key or was mistranscribed.",
        )
    return F


def restore_share(backup: Backup, F: list[GE]) -> None:
    """Check a share against the public polynomial F from another party.

    See "Restoring a share". Raise NotOnPolynomialError if the share is not on
    F, and MaliciousPolynomialError if it is but its polynomial checksum fails.
    """
    if backup.index == 0:
        raise ValueError("A #0 backup holds the secret itself, not a share")
    if evaluate_public(F, backup.index) != backup.scalar * G:
        raise NotOnPolynomialError(
            "not_on_polynomial",
            f"Share #{backup.index} is not on the polynomial: it is from a different "
            "key or was mistranscribed. Try again.",
        )
    if not verify_poly_checksum(backup, F):
        raise MaliciousPolynomialError(
            "malicious_polynomial",
            f"Share #{backup.index} is on the polynomial but its polynomial checksum "
            "fails: the polynomial was made to fit the share. Its source is malicious.",
        )


def reconstruct(backups: list[Backup], t: int | None = None) -> Scalar:
    """Recover the secret s from #0 backups or from share backups.

    See "Reconstruction". #0 backups are recovered on their own: each must
    pass its polynomial checksum against its own public key s·G, and they must
    agree. Shares are verified together (the threshold t is found if not
    given), and s is interpolated at 0 from t of them.
    """
    if backups and all(backup.index == 0 for backup in backups):
        s = backups[0].scalar
        for backup in backups:
            if not verify_poly_checksum(backup, [backup.scalar * G]):
                raise RecoveryError(
                    "poly_checksum",
                    "Polynomial checksum failed for backup #0: it was mistranscribed "
                    "or is corrupted",
                )
            if backup.scalar != s:
                raise RecoveryError(
                    "whole_keys_disagree", "The #0 backups encode different secrets"
                )
        return s

    F = verify_together(backups, t)
    points = list({backup.index: backup.scalar for backup in backups}.items())
    points = points[: len(F)]
    s = Scalar(0)
    for x_i, y_i in points:
        coefficient = Scalar(1)
        for x_j, _ in points:
            if x_j != x_i:
                coefficient *= Scalar(-x_j) / (x_i - x_j)
        s += y_i * coefficient
    return s
