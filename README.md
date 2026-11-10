```
  BIP: ?
  Layer: Applications
  Title: Mnemonic Backups for secp256k1 Keys and Shares
  Authors: Lloyd Fournier <lloyd@frostsnap.com>
           Nick Farrow <nick@frostsnap.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Requires: 32, 39, 341, 386, 389
```

## Abstract

This document specifies a backup format that encodes a secp256k1 secret key as a
share index followed by 25 words from the [BIP39] English wordlist.

By encoding the secret key directly, rather than entropy to be hashed into a
key, this format backs up either the key itself or a [Shamir secret
share][sss] of it, as in [FROST] wallets where the key is never
reconstructed in one place. Several devices can each contribute entropy to
such a key without any one of them ever holding it. Existing backup formats,
such as [BIP39], [SLIP39] and [BIP93], back up entropy that a one-way hash turns
into the key. One device must therefore hold every byte that is backed up, and
the resulting key. A key generated jointly by several devices cannot be backed
up this way: the key already exists, and no one knows entropy that hashes to it.

The format includes an 11-bit checksum to detect transcription errors and an
8-bit polynomial checksum that binds the backup to the public polynomial it was
generated against, and therefore to the public key.

## Motivation

A [BIP39] mnemonic does not back up a key; it backs up _entropy_. Turning that
entropy into usable keys and addresses requires hashing it: PBKDF2 to derive the
seed, then HMAC-SHA512 to derive the [BIP32] master key. Each of these hashes
needs the whole secret in one place. A hash is not homomorphic, so it cannot
practically be computed across participants. Needing the whole secret in one
place has two consequences:

- **You trust one device.** A single machine holds the whole secret and both
  _generates its randomness_ and converts it into the public keys and addresses
  you will receive to. Without independent verification on a second device, you
  have to trust it on both counts.
- **The key cannot be generated collaboratively.** There is no practical way
  for several parties to verifiably contribute to the secret, because the
  entropy-to-key hash cannot be evaluated efficiently across parties.

The ecosystem works around this awkwardly. Some hardware wallets already run
anti-exfil protocols so that a device cannot bias its _signing nonces_, yet those
same devices generate the far more valuable _secret key_ unchecked.
Cautious users resort to manual rituals (rolling dice, flipping coins, drawing
words from a hat). But even then a device must convert that secret entropy into
an extended private key, and that into public keys and addresses. Checking that
it did so faithfully takes a second, independent _verifier_ device. Distributed
key generation (DKG) and related distributed-randomness protocols solve the
problem properly: multiple parties verifiably contribute entropy, no single
party ever holds the secret, and every participant verifies the resulting public
key through the protocol itself.

This format backs up the **secret key itself**. A key's public form `s·G` is
homomorphic, so the key can be generated interactively, with no single device
dictating the resulting addresses. The scheme extends naturally to
[Shamir secret shares][sss], since a share is itself just a secret scalar.

Whether backing up a whole key or a share of a key, users need a format that is:

- **Paper-friendly and checksummed:** written by hand onto durable media, with
  an 11-bit checksum that catches a word miscopied when writing the backup down
  or mistyped when entering it back in.
- **Familiar:** reusing the BIP39 English wordlist, which users and tooling
  already know.
- **Bound to its key:** able to detect after restoration that a backup is
  being associated with the wrong public key, for example by a dishonest
  coordinating device in a multiparty wallet. Script multisignature wallets
  suffer the same problem largely unaddressed: nothing in the format checks
  that a restored seed is being paired with the right descriptor and
  co-signers, and users rarely verify this by other means.
- **Interoperable:** recoverable from the written words by any implementation
  of this specification, so funds do not depend on the wallet that created the
  backup.

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY in this document are
to be interpreted as described in [RFC 2119][RFC2119] and [RFC 8174][RFC8174]
when, and only when, they appear in all capitals.

A backup encodes only secret key material and its checksums. It carries no
[output descriptor][BIP380], derivation policy, address labels or other wallet
metadata: everything else is derived deterministically from the key (see
[Bitcoin wallet derivation](#bitcoin-wallet-derivation) below). Nor does it
record the threshold (see [Rationale](#rationale)).

A key with recovery threshold `t` is described by a _secret polynomial_ `f`
with `t` coefficients, whose constant term is the secret key `s`:

```
f(x) = a_0 + a_1·x + … + a_(t-1)·x^(t-1),        s = f(0) = a_0
```

A backup holds one point `(i, f(i))`, written `#i`. `#0` is the secret itself
and is used only for keys with threshold `1`, where `f` is the constant `s`.
Otherwise backups are _shares_ `#1`, `#2`, …, any `t` of which determine `f` and
so `s`. Shares can be dealt by Shamir secret sharing or produced by a DKG, and
both can be backed up using this encoding.

Multiplying by the secp256k1 generator `G` gives the _public polynomial_
`F(x) = f(x)·G`. Its coefficients are the points `A_j = a_j·G`:

```
F(x) = A_0 + A_1·x + … + A_(t-1)·x^(t-1)
```

Anyone holding the coefficients `A_j` can evaluate the public polynomial without
knowing any secret. Its value at `0` is the public key `A_0 = s·G`, and its
value at `i` is `f(i)·G`, the _public image_ of share `i`. The public polynomial
can also be interpolated from any `t` public images without assembling the
secret. In a DKG no one ever knows the secret polynomial, but every participant
learns the public one.

### Textual format

A backup consists of a `#` symbol, followed by a share index, followed by 25
words:

```
#<share_index> <word_1> <word_2> ... <word_25>
```

- The `share_index` is a decimal integer, the x-coordinate `i` of the point.
  It MUST fit in an unsigned 32-bit integer. Key generation SHOULD number
  shares sequentially from `1` (`1`, `2`, `3`, …), so that indices stay short
  enough to write.
- Each word is from the [BIP39] English wordlist. A decoder MUST reject a backup
  that does not have exactly 25 words, or one that contains a word not in the
  wordlist. Words are case-insensitive on input. Canonical output is UPPERCASE,
  with the index and the 25 words separated by single ASCII spaces.

Example: a `#0` backup of the secret `0x0101…01`, a `1`-of-`1` key (the first
entry under [Test vectors](#test-vectors)). The 25 words carry the scalar and
the two checksums defined in the sections that follow:

```
#0 ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CHECK WIDTH
```

### Bit layout

As in [BIP39], each word encodes 11 bits (`0`–`2047`), given by its position
in the wordlist. The 25 words therefore carry `25 × 11 = 275` bits.
Concatenating each word's 11 bits, most significant bit first, with words taken
left to right, yields a single 275-bit string, partitioned as follows:

| Bits    | Length | Words | Content                          |
| ------- | ------ | ----- | -------------------------------- |
| 0–255   | 256    | 1–24  | Secret scalar (big-endian)       |
| 256–263 | 8      | 24    | Polynomial checksum              |
| 264–274 | 11     | 25    | Words checksum                   |

Word 24 straddles the boundary: its top 3 bits are the final 3 bits of the
scalar, and its low 8 bits are the polynomial checksum. Word 25 is exactly the
11-bit words checksum.

### Secret scalar

Bits 0–255 are a 32-byte big-endian secp256k1 scalar: the value
`f(i)` of the secret polynomial. The 32 bytes, read as an integer,
MUST be less than the secp256k1 group order
`N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`;
a decoder MUST reject a backup whose scalar is not.

### Checksums

Both checksums are derived from a [SHA256] hash. They share two common inputs:

- `secret_scalar`: the 32-byte big-endian scalar above.
- `share_index`: the share index. The polynomial checksum encodes it as a
  32-byte secp256k1 scalar, the words checksum as a 4-byte big-endian `u32`;
  each subsection below gives the exact encoding.

#### Polynomial checksum

The polynomial checksum binds the backup to the public polynomial `F` it was
generated against, and therefore to the public key `A_0`. The public
polynomial also fixes the threshold and the public image of every share, so the
checksum ties the backup to the set of shares it belongs to (one key can be
reshared many times, each time into a different set). Its third input is:

- `polynomial_commitment`: the coefficients of `F` concatenated in order,
  constant term (the public key) first, `33·t` bytes in all:

  ```
  polynomial_commitment = ser(A_0) || ser(A_1) || ... || ser(A_(t-1))
  ```

  where `ser` is 33-byte compressed point serialization. For a key with
  threshold `1` this is just the public key, `ser(s·G)`. Implementations MUST
  serialize `polynomial_commitment` exactly as defined here.

The checksum is the first byte of a hash over all three inputs:

```
H = SHA256( share_index_32 || secret_scalar || polynomial_commitment )
poly_checksum = H[0]            // the top 8 bits, one byte
```

where `share_index_32` is the index as a 32-byte big-endian secp256k1 scalar.

This checksum is verified against the public polynomial `F`. A `#0` backup's
`F` is its own public key `s·G`, which the backup itself produces, so it can be
checked immediately. That adds 8 bits of error detection but cannot show the
key is the one you expected. For that, compare `s·G` with the expected public
key directly. For any other backup, `F` comes from elsewhere: a device restoring
one share receives it from another party that stored it after key generation,
such as the wallet's coordinator (see
[Restoring a share](#restoring-a-share)), and a recovery from backups alone
interpolates it from the public images of any `t` shares, without assembling
the secret (see [Verifying backups together](#verifying-backups-together)).

#### Words checksum

The words checksum detects transcription errors and is verified immediately
upon input, using only the data carried by the backup itself. Its third input
is the polynomial checksum:

```
H = SHA256( share_index_4 || secret_scalar || 0x00 || poly_checksum )
words_checksum = (H[0] << 3) | (H[1] >> 5)        // the top 11 bits
```

where `share_index_4` is the index as a 4-byte big-endian `u32`, and
`0x00 || poly_checksum` is the 1-byte polynomial checksum widened to a 2-byte
big-endian integer. The resulting 11-bit value is the position of word 25 in
the wordlist.

On decoding, a backup whose recomputed `words_checksum` does not match word 25
MUST be rejected as mistranscribed. A mistranscribed backup still passes with
probability `1/2048`. Implementations MUST NOT attempt to correct a failing
backup automatically. A single wrong word typically has about 25 one-word
corrections that would satisfy the words checksum, so an automatic correction is
usually wrong.

### Share generation

Backing up a share `(i, f(i))` requires the public polynomial `F` as well as
the scalar `f(i)`, since the polynomial checksum is computed over both. Key
generation supplies `F`: either a trusted dealer provides it, or a DKG computes
it. A key with threshold `1` MUST be backed up as `#0`, regardless of how it was
generated or how many copies are made. Its `F` is just `s·G`, so knowing the
secret alone suffices. The rest of this section concerns keys with threshold
`t ≥ 2`, whose shares MUST NOT use index `0`: the point `(0, f(0))` is the
secret itself.

With a trusted dealer, shares of a secret `s` (a non-zero secp256k1 scalar)
for threshold `t` and share count `n` (`2 ≤ t ≤ n`) are produced as follows:

1. Set `a_0 = s`, choose the other coefficients `a_1, …, a_(t-1)` of `f`
   uniformly at random, and compute the public polynomial's coefficients
   `A_j = a_j·G`.
2. Grind the fingerprint into the public polynomial and apply the same tweak
   to the secret polynomial `f` (see [Fingerprint](#fingerprint)); the tweaked
   `f` is used in the step below.
3. For each `i` from `1` to `n`, evaluate `y_i = f(i)`, compute the polynomial
   checksum for `(i, y_i)`, and encode `#i` with the 25 words as above.

In a DKG no such dealer exists. The DKG leaves each participant holding a share
`(i, f(i))` of a polynomial `f` that no one knows in full, along with its public
polynomial `F`. Before the participants' final agreement on `F`, the fingerprint
MUST be ground into it and every share MUST be updated by the resulting tweak
(see [Fingerprint](#fingerprint)). Grinding needs only the public polynomial, so
any party can do it. Before encoding its share as a backup, each participant's
implementation MUST check that the agreed polynomial carries the fingerprint.

#### Fingerprint

The fingerprint allows a collection of backups to be recognized as belonging
together. Key generation MUST embed the `frost-v0` fingerprint in the public
polynomial of every key with threshold `2` or more, so that backups are
recoverable across systems. It is embedded by _grinding_, a small proof-of-work:
non-constant coefficients `A_j` are repeatedly incremented by `G` (and `a_j` by
`1`) until a running [SHA256] hash over the coefficients has enough leading zero
bits. The `frost-v0` parameters are `tag = "frost-v0"` (ASCII),
`bits_per_coeff = 18` and `max_bits_total = 36`:

```
state = new SHA256 hash
update(state, byte(len(tag)) || tag || ser(A_0))
bits = 0
for j from 1 to t-1:
    needed = min(bits_per_coeff, max_bits_total - bits)
    if needed == 0: break
    while leading_zero_bits( digest_with(state, ser(A_j)) ) < needed:
        A_j = A_j + G        // and, secret side, a_j = a_j + 1
    update(state, ser(A_j))
    bits = bits + needed
```

where `update(state, X)` absorbs `X` into the running hash;
`digest_with(state, X)` is the digest the hash would have after absorbing `X`,
without changing `state`; `byte(len(tag))` is the tag's length as a single
byte; `ser` is the 33-byte compressed serialization above; and
`leading_zero_bits` counts the zero bits at the start of the 32-byte digest,
most significant bit first.

To verify that a public polynomial carries the fingerprint, run the same loop
without grinding: it passes if, at every step, the running digest has at least
`needed` leading zero bits.

The constant term is never tweaked, so grinding changes neither the secret
`f(0)` nor the public key. Each ground coefficient costs about
`2^bits_per_coeff` hashes. Since `max_bits_total` is twice `bits_per_coeff`,
at most the first two non-constant coefficients are ground. A key with threshold
`1` has no non-constant coefficients, so it carries no fingerprint.

If shares already exist when the fingerprint is ground, they are updated to
match. Let `k_j` be the number of times `G` was added to `A_j`. The tweak
polynomial `g(x) = k_1·x + … + k_(t-1)·x^(t-1)` is public, and each share
`(i, y)` becomes `(i, y + g(i))`.

### Verifying backups together

For threshold `t ≥ 2`, a set of share backups is checked against the public
polynomial without assembling the secret. A `#0` backup is not a share and is
left out: it lies on every public polynomial of its key, since `F(0) = s·G`,
and is recovered on its own (see [Reconstruction](#reconstruction)). Write each
backup as `(x_i, y_i)`, its index and its scalar:

1. Interpolate `F` from the public images `y_i·G` of any `t` of the backups.
   If its last coefficient `A_(t-1)` is the point at infinity, the backups lie
   on a polynomial of lower degree, and the threshold is not `t`.
2. Confirm that `F` carries the `frost-v0` fingerprint (see
   [Fingerprint](#fingerprint)).
3. Confirm that every other backup lies on `F`: `F(x_i) = y_i·G`.
4. Verify each backup's polynomial checksum against `F`.

A set that fails any step MUST be rejected. If the fingerprint check fails, at
least one of the `t` backups is from a different key or was mistranscribed. With
exactly `t` backups there is no telling which. With more than `t`, an
implementation can search for a subset of `t` backups whose interpolated
polynomial passes the fingerprint; the backups that do not lie on that
polynomial belong elsewhere and are set aside. Interpolation needs distinct
indices, so a subset never contains two backups with the same index (shares of
different keys usually both start at `#1`). Trying subset sizes from `2` up (a
single share has no fingerprint to check), the same search finds `t` when it is
not known. A threshold-`2` fingerprint has only `18` bits, so two shares of a
larger key pass its check by chance about once in `2^18` tries. After a
threshold-`2` match, a search should therefore keep trying larger subsets, and
prefer a larger one that passes. From threshold `3` up the fingerprint has `36`
bits, which a chance match passes only about once in `2^36` tries, so the search
can stop at the first match. Every backup that lies on a polynomial found this
way MUST still pass its polynomial checksum against it.

### Restoring a share

A share `(i, y)` is usually restored onto a signing device, which receives the
public polynomial `F` from another party, such as the coordinator of a
multiparty wallet. After checking the words checksum, the device:

1. Confirms that the share lies on the polynomial: `F(i) = y·G`. If it does
   not, the backup is from a different key or was mistranscribed, and the user
   can try again.
2. Verifies the polynomial checksum against `F`. Because the share lies on `F`,
   a mismatch almost certainly means the polynomial was constructed to fit the
   share. The device MUST then treat the polynomial's source as malicious and
   warn the user, and MUST NOT retry with a different polynomial.

### Reconstruction

For a `#0` backup, recovery is decoding it and verifying its
checksums. The backup holds the entire secret, so no interpolation is needed.

Reconstruction from shares is a last resort in threshold settings: [FROST]
wallets sign without ever assembling the secret key, but the procedure below
assembles it on one device, making that device a single point of failure. It is
an alternative path to recovery for when distributed signing is unavailable, and
SHOULD NOT be used otherwise.

Given `t` or more share backups:

1. Verify each backup's words checksum on input.
2. Verify the backups together (see
   [Verifying backups together](#verifying-backups-together)).
3. Recover the secret via Lagrange interpolation over the secp256k1 scalar
   field, evaluating at `x = 0` over `t` of the backups `(x_i, y_i)`:

   ```
   s = Σ_i  y_i · Π_{j≠i} ( -x_j / (x_i - x_j) )   (mod N)
   ```

   The Lagrange coefficients are computed modulo `N`, using a modular inverse.

### Bitcoin wallet derivation

The secret `s` is interpreted as the root private key of a [BIP32] HD wallet
with an all-zero chain code, and the public key `A_0` as its root public key.
BIP32 calls this root the master key, `m`. Where the secret is held whole (as
with a `#0` backup or after reconstruction), it is serialized as an extended
private key with zero depth, zero parent fingerprint, zero child number and an
all-zero chain code. The serialization uses the standard [BIP32] version bytes
`0x0488ADE4` (mainnet `xprv`) or `0x04358394` (testnet `tprv`) and is
[Base58Check]-encoded as specified in [BIP32].

Wallets MUST derive addresses with the following [Taproot][BIP341] output
descriptor ([BIP386]), shown with the `xprv`:

```
tr(xprv/0/0/0/0/<0;1>/*)
```

where the path components, all defined by this convention, are in order:
application key (`0`), application (`0` = Bitcoin), account type
(`0` = Taproot), account index (`0` for the first account), keychain
(`<0;1>` = receive/change, in [BIP389] multipath notation) and address index
(`*`).

A wallet MAY use further accounts by incrementing the account index; recovery
tools SHOULD scan account indices upward from `0`.

A fixed descriptor convention belongs in this document because a key held in
shares cannot use hardened derivation, which hashes the parent secret key that
no party holds whole. Every derivation step below the root key is therefore
unhardened, and fixing the
path and the chain code by convention means the written words alone are
sufficient to recover the wallet and its addresses. Hardened-style derivation
for multiparty keys is left to future work.

Because every step is unhardened, anyone holding an extended public key can
derive every public key beneath it. With its all-zero chain code, the root
public key `A_0` alone is such a key: it, and the public polynomial `F` that
contains it, reveal every address, and should be kept as private as an `xpub`. A
wallet SHOULD therefore export its watch-only descriptor from the `xpub` of its
account key (`m/0/0/0/0` for the first account), which gives the same addresses
but nothing above or beside that account. The first step, to the application key
`m/0`, leaves the root key free for an implementation's own use.

## Rationale

The format balances several desired properties: backup length (fewer words to
write down), familiarity (a wordlist users and tooling already know),
resistance to transcription errors, and simplicity (so that the scheme is easy
for other engineers to implement and adopt).

- **BIP39 words over [bech32][BIP173] characters:**
  users already recognize these words, and a wide range of tooling (hardware
  wallets, printed cards) supports them. Familiar words are also far easier to
  copy by hand than random characters (hex, Base58 or bech32). The writer knows
  how each word is spelled, so a slip shows up as a misspelling they can notice
  and fix as they write. [BIP39] chose its words with this in mind: each is
  unique in its first four letters, and near-duplicates such as build/built are
  excluded. Backups remain clearly distinguished from BIP39 mnemonics by the
  leading `#index` and the 25-word length; see
  [Backwards compatibility](#backwards-compatibility).
- **SHA256 checksums over Reed–Solomon:** a Reed–Solomon check word would
  guarantee detection of any single-word error, where the hash checksum misses
  with probability `1/2048`. That marginal gain is not worth the added
  implementation complexity; following [BIP39]'s hash-based approach keeps the
  format easy to reimplement independently.
- **An 8-bit polynomial checksum:** eight bits suffice to deter key
  substitution, because each share's checksum is bound to that share's own
  secret scalar, which a malicious coordinator does not know. Holding other
  shares does not help it: fewer than `t` shares do not determine another, so
  it still cannot forge the checksum of a share it lacks. The
  coordinator can always construct a public polynomial that is _consistent_
  with a share: it knows the share's public image `F(i)`, and for a constant
  term of its own choosing can solve for the remaining coefficients.
  Consistency alone therefore does not protect against key substitution. The
  checksum does, because the coordinator cannot evaluate `H` without
  `secret_scalar`. It cannot search offline for a substitute polynomial that
  passes, so it is left with a single blind guess that succeeds with
  probability `1/256`. [Restoring a share](#restoring-a-share) forbids a second
  guess.
- **Fingerprint parameters:** grinding cost is exponential in the bits per
  coefficient but linear in the number of coefficients, so spreading `36` bits
  over two coefficients costs about `2^19` hashes rather than `2^36`. At `36`
  bits a wrong set of backups passes by accident with probability only `2^-36`,
  so further coefficients are not ground. A key with threshold `2` has only one
  coefficient to grind and gets `18` bits.
- **Sequential share indices:** simple and deterministic; the index doubles as
  the number written after `#`, so small sequential indices keep it short
  enough to write.
- **Related work ([SLIP39]):** SLIP39 also encodes Shamir shares as mnemonic
  words, but over `GF(256)` with its own wordlist. A `GF(256)` share admits no
  elliptic-curve arithmetic, so SLIP39 shares cannot serve threshold-signing
  protocols such as [FROST]. This scheme instead operates on the secp256k1
  scalar field the keys already live in and reuses the BIP39 wordlist.
- **No threshold in the backup:** the threshold `t` and share count `n` are not
  encoded. The 25 words have no spare bits, and a readable encoding would cost
  a whole extra word. The threshold is not secret, so it can be written next to
  each backup instead (for example `2-of-3`, with the wallet's name), and `#0`
  declares `t = 1`. If the threshold of a set of shares is lost, a recovery tool
  can still find it by searching subset sizes from `2` up for one whose
  interpolated polynomial passes the fingerprint check.
- **No passphrase:** unlike [BIP39] and [SLIP39] there is no passphrase and no
  decoy wallet. For shares, security comes from geographic separation. A `#0`
  backup, like a BIP39 mnemonic without a passphrase, gives anyone who finds it
  the whole key. If desired, a future specification could layer a passphrase on
  top without changing this encoding.

## Backwards compatibility

These backups are **not** BIP39 mnemonics, and users should never enter them
into BIP39 tooling. They differ visibly: each begins with a mandatory `#index`
prefix and is 25 words long, where BIP39 mnemonics have no prefix and are 12–24
words. Structurally each carries a raw scalar plus two purpose-built checksums
rather than BIP39's entropy-plus-checksum layout.

If a user does enter one, BIP39 tooling will rarely accept it. A user who
ignores the share index might enter the first 24 words as a 24-word mnemonic,
with the 25th word as a passphrase; BIP39's 8-bit checksum then rejects them
with probability `255/256`.

## Test vectors

Every valid vector with threshold `2` or more carries the `frost-v0`
fingerprint. Reconstructing any `t` of the listed shares yields the stated
secret. Interpolating their public images yields the listed polynomial
commitment (one 33-byte coefficient per line), against which every share's
polynomial checksum verifies.

### 1-of-1

Secret: `0x0101010101010101010101010101010101010101010101010101010101010101`

Polynomial commitment:

```
031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f
```

```
#0 ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CHECK WIDTH
```

### 2-of-3

Secret: `0x0101010101010101010101010101010101010101010101010101010101010101`

Polynomial commitment:

```
031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f
0214ec06c944abcb9245902e82e37a23896a4069fd86ad7ae2f9cb91c59109109a
```

```
#1 MUTUAL JEANS SNAP STING BLESS JOURNEY MORAL BREAD ROOM LIMIT DOSE GRAVITY SORT DELIVER OUTDOOR RIPPLE DONKEY BLOUSE PLAY CART CENTURY MAXIMUM MAKE LOCAL MOBILE
#2 CASH TRASH FOIL PREFER BUTTER IDEA BRAVE BITTER ITEM WINK DRIFT SMILE TOMATO LUNCH OPTION HERO THREE ENGINE BLESS MANAGE HORSE JAR ADVICE SHERIFF BUSINESS
#3 REGION FINISH TRAVEL LAUNDRY CHEAP HAIR PLUNGE BANANA CRACK INTEREST DURING COTTON PHONE DISAGREE CRUNCH AIRPORT CANCEL FOLD LAUNDRY PONY LOBSTER LENS MAMMAL CLOTH FINGER
```

### 3-of-5

Secret: `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`

Polynomial commitment:

```
02c6b754b20826eb925e052ee2c25285b162b51fdca732bcf67e39d647fb6830ae
020edcb4850d4cd9a57009e9900bf54acdb240a2087e6071a3616808d73c8424f1
029cf188eac4090ee194ca695133762e1ad22e709cf2a7e16d5494bfcfd245e25d
```

```
#1 DUTCH GLAD TORCH EXACT PROGRAM GRASS CLUB SCRAP MUSCLE TUITION TISSUE CLERK SEA SUMMER SHIP VERY FREQUENT DIAL SYRUP MAMMAL SIMILAR MISERY PLAY RING ARM
#2 SUGAR GENERAL PARK VOYAGE CREEK FLY MOTOR ALWAYS WAVE SUNNY WARRIOR DIAMOND WAVE SUNSET ANY LEFT LIGHT FLOAT VAULT GENUINE ELBOW TENNIS BECOME TABLE CLAIM
#3 ORANGE HAMMER UNFOLD REFUSE IMMUNE FAVORITE POET MEDIA CARRY SEGMENT PULL BRUSH DAMAGE ADDRESS FILE PORTION UNFOLD BLAST ACCOUNT NATION TELL BELT DENY ABILITY FOOD
#4 MIRACLE KETCHUP SLIM MAZE GUESS FEBRUARY IDLE ENDORSE BARELY POLAR AGAIN SIBLING CLARIFY SHELL EAGER FISCAL DISTANCE FEW ABOVE SURE FRAME ENFORCE BUTTER MORNING ZOO
#5 PUMPKIN NEUTRAL DESTROY INSTALL BEHAVE FOLD UNDER EAST SHORT MAGNET WORLD DEVICE SPECIAL BUYER STONE MILLION JUNIOR BEAN UPON CRYSTAL SCENE LEARN SEARCH GALAXY SUMMER
```

### 4-of-4

Secret: `0x0202020202020202020202020202020202020202020202020202020202020202`

This vector tests the fingerprint's `max_bits_total` cap. Only `A_1` and `A_2`
are ground, so `A_3` carries no fingerprint bits. An implementation that
demands `bits_per_coeff` leading zero bits for every coefficient wrongly
rejects it.

Polynomial commitment:

```
024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766
020313fcdea366087be6d6e3f6dda8e94206ab2ecf4bc9c0579fabe53a8be6133a
02a1870d54e1745899c36a2b5ad8d0d3954d7fe8a596bf5c1c2b6f8d5f66b1e179
03ffa2679439054ac606a004ca7a304f0870d6d2e76a2be48f9c033046e96c39b6
```

```
#1 CAT WITNESS MARINE SAVE SHOCK DEVELOP CHAOS DEVELOP SMOOTH SELECT RUG FATIGUE CITIZEN OBSCURE DINOSAUR ROOF ACTOR ALCOHOL SCREEN DEMAND PATH DOLPHIN FATIGUE INSECT FORCE
#2 ARTWORK REUNION SECOND TURKEY COMMON CONNECT EQUIP HOTEL AFFORD CLOCK SHRIMP OCTOBER OBJECT SHIELD JEALOUS OBVIOUS ARMOR BURDEN HABIT SHIP EYE WORTH TOP OBJECT BEGIN
#3 TRULY REPAIR WHEAT BRIDGE CANYON STUMBLE DRAMA EDGE GORILLA GROUP MANAGE ORANGE RACCOON VOICE BITTER MARKET ISSUE JOURNEY DELIVER TURN MEDAL MAN SPIRIT WEIRD REFORM
#4 TOMATO HELP WEAR TUNNEL HEAD CRUISE SPAWN CUSTOM PRETTY NEITHER TONE CLOG RELIEF ELSE QUARTER LEND ROBOT OBVIOUS BUS REGION DILEMMA SUCCESS CARRY INJECT BOARD
```

### Wallet derivation

The 1-of-1 and 2-of-3 vectors share the secret `0x0101…01`. Its root extended
private key, and its first addresses under the descriptor in
[Bitcoin wallet derivation](#bitcoin-wallet-derivation), are:

Root `xprv`:

```
xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93yjHmmfwkTW7jWmaf7X9aF3GP9D3mXSChQcm2zAZG6kerWdMw
```

First receive address (`m/0/0/0/0/0/0`):

```
bc1pep252ktfxrz05jxzk4ts93jpxz6hurx2nz82yac4slxyzk2r06xq86fjw2
```

First change address (`m/0/0/0/0/1/0`):

```
bc1pdx4z22rx7pe9gps3mal0naczs2aqprms9upfpul506hrl5nknsdsqec4e3
```

### Invalid backup (words checksum failure)

The following is backup `#1` of the 2-of-3 vector with the final word changed
from `MOBILE` to `ABANDON`. A conforming decoder MUST reject it:

```
#1 MUTUAL JEANS SNAP STING BLESS JOURNEY MORAL BREAD ROOM LIMIT DOSE GRAVITY SORT DELIVER OUTDOOR RIPPLE DONKEY BLOUSE PLAY CART CENTURY MAXIMUM MAKE LOCAL ABANDON
```

A backup with fewer or more than 25 words, or with a word absent from the BIP39
English wordlist, is likewise rejected (see [Textual format](#textual-format)).

### Invalid backup (scalar out of range)

The following backup `#1` encodes the scalar `N` itself, with a polynomial
checksum of `0` and a valid words checksum. A conforming decoder MUST reject it
(see [Secret scalar](#secret-scalar)):

```
#1 ZOO ZOO ZOO ZOO ZOO ZOO ZOO ZOO ZOO ZOO ZOO WORD PRIORITY HOVER ONE TROUBLE PARENT TARGET VIRUS RUG SNACK BRASS AGREE CACTUS MIRACLE
```

### Invalid backup (polynomial checksum failure)

The following is backup `#1` of the 2-of-3 vector with every bit of its
polynomial checksum flipped and word 25 recomputed, so the words checksum still
passes. A decoder accepts it on input, but verification against the 2-of-3
polynomial commitment above MUST fail:

```
#1 MUTUAL JEANS SNAP STING BLESS JOURNEY MORAL BREAD ROOM LIMIT DOSE GRAVITY SORT DELIVER OUTDOOR RIPPLE DONKEY BLOUSE PLAY CART CENTURY MAXIMUM MAKE ORIGINAL IMPULSE
```

### Invalid `#0` backup (polynomial checksum failure)

The following is the `#0` backup of the 1-of-1 vector with every bit of its
polynomial checksum flipped and word 25 recomputed, so the words checksum still
passes. A decoder accepts it on input, but verification against its own public
key `s·G` MUST fail:

```
#0 ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE DECLINE SILK
```

### Invalid set (fingerprint failure)

The following two backups are shares of a `2`-of-`2` key whose public
polynomial was never ground, so it does not carry the `frost-v0` fingerprint.
Both pass their words checksums, and both polynomial checksums verify against
the polynomial commitment below. A conforming implementation MUST still reject
the set (see [Verifying backups together](#verifying-backups-together)). This
vector catches an implementation that skips the fingerprint check.

Polynomial commitment:

```
02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337
03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b
```

```
#1 ALPHA DEAL SCRUB ASTHMA IDEA LOGIC BRIGHT THOUGHT ALPHA DEAL SCRUB ASTHMA IDEA LOGIC BRIGHT THOUGHT ALPHA DEAL SCRUB ASTHMA IDEA LOGIC BRIGHT WINDOW BARELY
#2 ARCH FLAME SECURITY BID RADAR MACHINE CLUB GESTURE ARCH FLAME SECURITY BID RADAR MACHINE CLUB GESTURE ARCH FLAME SECURITY BID RADAR MACHINE CLUB GLOOM INFORM
```

## Reference Implementation

- **Python:** a [reference implementation][reference] of everything in this
  document, from decoding a backup to deriving the wallet's addresses. It
  generates the test vectors above as [JSON][vectors], adding one for
  fingerprint grinding. It is slow and not constant-time, and must not be used
  with real keys.
- **Rust:** the [`frost_backup`][frost_backup] crate, used by Frostsnap devices
  and the Frostsnap app.
- **Recovery tool:** [frostsnap-thaw][thaw], a Python program that recovers a
  wallet from its backups, for emergencies when distributed signing is not
  available. The reference implementation was derived from it.

## Copyright

This BIP is licensed under the BSD-2-Clause license.

[sss]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
[BIP32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[BIP39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[BIP173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
[BIP341]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
[BIP380]: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
[BIP386]: https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki
[BIP389]: https://github.com/bitcoin/bips/blob/master/bip-0389.mediawiki
[FROST]: https://www.rfc-editor.org/rfc/rfc9591
[SLIP39]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
[BIP93]: https://github.com/bitcoin/bips/blob/master/bip-0093.mediawiki
[SHA256]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
[Base58Check]: https://en.bitcoin.it/wiki/Base58Check_encoding
[reference]: https://github.com/frostsnap/bip-secp256k1-backups/tree/master/python
[vectors]: https://github.com/frostsnap/bip-secp256k1-backups/tree/master/vectors
[frost_backup]: https://github.com/frostsnap/frostsnap/tree/master/frost_backup
[thaw]: https://github.com/frostsnap/frostsnap-thaw
