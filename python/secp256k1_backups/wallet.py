"""Bitcoin wallet derivation (see "Bitcoin wallet derivation" in the BIP)."""

import hashlib
import hmac

from secp256k1lab.secp256k1 import GE, G, Scalar
from secp256k1lab.util import tagged_hash

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GENERATOR = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
_BECH32M_CONST = 0x2BC830A3


def _base58check(payload: bytes) -> str:
    """Encode bytes with Base58Check, as BIP32 does for extended keys."""
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    digits = ""
    while n > 0:
        n, r = divmod(n, 58)
        digits = _BASE58_ALPHABET[r] + digits
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * zeros + digits


def _bech32m(hrp: str, data: list[int]) -> str:
    """Encode a list of 5-bit values as a bech32m string (BIP350)."""
    hrp_expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    chk = 1
    for value in hrp_expanded + data + [0] * 6:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= _BECH32_GENERATOR[i] if (top >> i) & 1 else 0
    chk ^= _BECH32M_CONST
    checksum = [(chk >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


def _ckd_pub(point: GE, chain_code: bytes, i: int) -> tuple[GE, bytes]:
    """Derive unhardened child `i` of an extended public key (BIP32 CKDpub)."""
    if not 0 <= i < 2**31:
        raise ValueError("child index must be unhardened")
    data = point.to_bytes_compressed() + i.to_bytes(4, "big")
    h = hmac.digest(chain_code, data, "sha512")
    child: GE = Scalar.from_bytes_checked(h[:32]) * G + point
    if child.infinity:
        raise ValueError("invalid child key")
    return child, h[32:]


def _taproot_output_key(internal_key: GE) -> bytes:
    """Tweak an internal key that has no script tree (BIP341, as in BIP86)."""
    p = internal_key.to_bytes_xonly()
    t = Scalar.from_bytes_checked(tagged_hash("TapTweak", p))
    q: bytes = (GE.from_bytes_xonly(p) + t * G).to_bytes_xonly()
    return q


def xprv(secret: Scalar, testnet: bool = False) -> str:
    """Serialize the secret as the wallet's root extended private key."""
    version = bytes.fromhex("04358394" if testnet else "0488ADE4")
    depth = bytes(1)
    parent_fingerprint = bytes(4)
    child_number = bytes(4)
    chain_code = bytes(32)
    key = b"\x00" + secret.to_bytes()
    return _base58check(
        version + depth + parent_fingerprint + child_number + chain_code + key
    )


def descriptor(secret: Scalar, testnet: bool = False) -> str:
    """Return the wallet's Taproot output descriptor, without a checksum."""
    return f"tr({xprv(secret, testnet)}/0/0/0/0/<0;1>/*)"


def address(
    secret: Scalar, keychain: int, index: int, account: int = 0, testnet: bool = False
) -> str:
    """Return the address at m/0/0/0/<account>/<keychain>/<index>."""
    point: GE = secret * G
    chain_code = bytes(32)
    for i in [0, 0, 0, account, keychain, index]:
        point, chain_code = _ckd_pub(point, chain_code, i)
    program = _taproot_output_key(point)
    # Witness version 1, then the 256-bit program zero-padded to 52 5-bit values.
    n = int.from_bytes(program, "big") << 4
    data = [1] + [(n >> 5 * i) & 31 for i in reversed(range(52))]
    return _bech32m("tb" if testnet else "bc", data)
