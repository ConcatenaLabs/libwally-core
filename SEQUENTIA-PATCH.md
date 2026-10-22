# The Sequentia patches

This document describes the three Sequentia changes in this fork of
[ElementsProject/libwally-core](https://github.com/ElementsProject/libwally-core).
All live on branch `sequentia-issuance-denomination`, on top of the upstream
tag `release_1.4.0`. All other branches are unpatched upstream.

Sequentia is a Bitcoin sidechain for asset tokenization and disintermediated
exchanges, built on Blockstream Elements (node repository:
https://github.com/ConcatenaLabs/Sequentia).

## 1. The issuance denomination byte

### Background

The Sequentia node extends the Elements asset-issuance structure
`CAssetIssuance` with a per-asset decimal-precision field:

```cpp
// Sequentia node, src/primitives/confidential.h
uint8_t nDenomination = 8;

SERIALIZE_METHODS(CAssetIssuance, obj) {
    READWRITE(obj.assetBlindingNonce, obj.assetEntropy,
              obj.nAmount, obj.nInflationKeys, obj.nDenomination);
}
```

Every serialized issuance therefore carries one extra byte relative to stock
Elements.

### Wire-format difference

An Elements transaction input signals an issuance by setting the flag bit
`WALLY_TX_ISSUANCE_FLAG` (`0x80000000`) in the outpoint index. For such an
input (excluding coinbase), the issuance payload following the sequence field
is:

| Field | Size | Stock Elements | Sequentia |
|---|---|---|---|
| `assetBlindingNonce` | 32 bytes | yes | yes |
| `assetEntropy` | 32 bytes | yes | yes |
| `nAmount` | confidential value (1, 9, or 33 bytes) | yes | yes |
| `nInflationKeys` | confidential value (1, 9, or 33 bytes) | yes | yes |
| `nDenomination` | 1 byte (`uint8_t`, decimal precision) | no | **yes** |

Stock libwally stops reading after `nInflationKeys`, so it is misaligned by one
byte for every issuance input in a Sequentia transaction. The practical
symptom: `wally_tx_from_bytes` returns `WALLY_EINVAL` on any Sequentia
issuance or reissuance transaction, and consumers that must parse every block
(such as a Lightning node) crash when they reach an issuance block.

### What the patch changes

All in the Elements-enabled build (`BUILD_ELEMENTS` / not
`WALLY_ABI_NO_ELEMENTS`):

1. `include/wally_transaction.h`: adds a public field at the end of the
   Elements section of `struct wally_tx_input`:

   ```c
   uint8_t issuance_denomination;
   ```

   It holds the parsed denomination for issuance inputs and is 0 for
   non-issuance inputs.

2. `src/transaction.c`, `analyze_tx`: when an input has the issuance flag set,
   requires and skips one extra byte after the two confidential values, so
   length validation matches the Sequentia layout.

3. `src/transaction.c`, `tx_from_bytes`: reads the byte after
   `nInflationKeys` and stores it into
   `wally_tx_input.issuance_denomination` after the input is initialized.

4. `src/transaction.c`, `get_txin_issuance_size`: adds
   `sizeof(input->issuance_denomination)` (1) to the computed issuance size,
   so length and weight calculations stay correct.

5. `src/transaction.c`, `tx_to_bytes`: re-emits the byte after the inflation
   keys when serializing an input with `WALLY_TX_IS_ISSUANCE` set.

6. `src/tx_io.c`, `hash_asset_issuance`: hashes the byte after the inflation
   keys. The node's signature hashes serialize the whole `CAssetIssuance`
   wherever they cover an issuance: the segwit v0 hash of every input's
   issuance and the signed input's own issuance, and taproot's
   `sha_issuances` and per-input issuance. Without the byte, every signature
   over a transaction that issues, on any of its inputs, is one the chain
   refuses.

Together, parse and serialize round-trip Sequentia issuance transactions
byte-exact, and signature hashes over them are the chain's. Inputs without
the issuance flag are handled identically to upstream.

## 2. The script-path signature hash on Elements

### Background

BIP341 ends the signature message of a script-path spend with the "tapscript
extension": the hash of the leaf being spent, a key version byte (0) and the
position of the last executed `OP_CODESEPARATOR`. The leaf hash is
`tagged_hash(tag, leaf_version || compact_size(len) || script)`.

Elements chains use their own tags (`TapLeaf/elements`,
`TapSighash/elements`, ...) and their own tapscript leaf version, `0xc4`
(Bitcoin's is `0xc0`). A Sequentia node computes the leaf hash in the
signature message with `0xc4`, as it does in the control block's merkle path.

### What the patch changes

`src/tx_io.c`, `txio_hash_tapleaf_hash`: hashes the leaf version as `0xc4`
when the transaction is an Elements one, and `0xc0` otherwise. Upstream hashes
`0xc0` in both cases, with the Elements tag, so every script-path signature
hash it produces for an Elements transaction differs from the one the chain
checks, and a signature over it is refused. Key-path signature hashes and all
Bitcoin signature hashes are unchanged: they have no tapscript extension, or
use `0xc0` as before.

`wally_tx_get_input_signature_hash` with `WALLY_SIGTYPE_SW_V1`, a leaf script
and an Elements transaction is the call this affects. Pass a key version of 0,
as BIP342 defines it for tapscript keys.

## 3. An issuance without a reissuance token, from a PSET

### Background

An issuance input that creates no reissuance token has a null token count
(`nInflationKeys`, one byte `0x00`). An explicit count of zero is not null:
the node checks it as an issued amount, refuses it for not being positive,
and the transaction fails with `bad-txns-in-ne-out`. The same holds for an
issuance amount of zero beside a non-zero token count.

### What the patch changes

`src/psbt.c`, `psbt_build_input`: when a PSET input carries unblinded
issuance values (`issuance_amount`, `inflation_keys`), each one that is zero
stays null in the extracted transaction instead of becoming an explicit zero.
Every path from a PSET to a transaction goes through it: `wally_psbt_extract`,
`wally_psbt_get_id` and the PSET signature hash functions.

A PSET has no field for the denomination, so an issuance extracted from one
has denomination 0. The chain attaches no rule to the value: it is display
precision only.

## Compatibility notes

- **Sequentia-only.** The patched branch assumes the Sequentia issuance
  layout. It will misparse stock Elements/Liquid issuance transactions (it
  would consume a byte that is not there). Do not use this branch against
  Liquid or vanilla Elements. The second patch is correct for every Elements
  chain.
- **ABI.** The new struct field changes the size of `struct wally_tx_input`
  in Elements-enabled builds relative to stock libwally 1.4.0. Build
  consumers from this source tree (as SeqLN does via a git submodule); do not
  mix this header with a stock libwally binary.
- **Base version.** The branch is based on upstream `release_1.4.0`. To move
  to a newer upstream release, cherry-pick the patch commits onto the new
  base; upstream 1.5.4 still hashes `0xc0` in `txio_hash_tapleaf_hash`.

## Consumers

[SeqLN](https://github.com/ConcatenaLabs/seqln) (branch `sequentia-stable`)
pins this branch through its `external/libwally-core` submodule (`.gitmodules`
sets `url = https://github.com/ConcatenaLabs/libwally-core.git`,
`branch = sequentia-issuance-denomination`).

## Tests

`src/test/test_sequentia_issuance.py` checks the first and third patches
against transactions a Sequentia node mined, each issuing one atom with no
token: they round-trip byte-exact with the node's txid; the node wallet's
segwit v0 signature, and a key-path taproot signature the node accepted,
verify over this library's signature hashes; and a PSET input issuing one
atom extracts to the node's transaction, denomination 0 and a null token
count. The tapleaf change is checked by SeqLN's
`common/test/run-tcov_scripts.c`, whose vectors come from the Sequentia
node's own test framework: the script-path hash, the key-path hash and a
`SIGHASH_SINGLE|SIGHASH_ANYONECANPAY` hash of one Elements transaction, and
BIP340 signatures over them.

`src/ctest/test_elements_tx` fails on this branch: its `test_tx_parse` vector
is a stock Elements issuance, without the denomination byte, which this
branch is built to read differently.
