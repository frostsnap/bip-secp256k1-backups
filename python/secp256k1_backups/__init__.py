"""Reference implementation of the BIP for mnemonic backups of secp256k1 keys
and shares.

It is slow and not constant-time, and must not be used with real keys. For
recovering a real wallet, use frostsnap-thaw.
"""

import sys
from pathlib import Path

# Prefer the vendored copy of secp256k1lab.
sys.path.insert(0, str(Path(__file__).parent / "../secp256k1lab/src"))
