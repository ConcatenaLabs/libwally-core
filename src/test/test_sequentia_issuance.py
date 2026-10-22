"""Sequentia issuances: signature hashes and PSET extraction.

A Sequentia asset issuance carries a denomination byte after the inflation
keys, and the node's signature hashes serialize the whole issuance, that byte
included.  An issuance that creates no reissuance token says so with a null
token count: the node refuses an explicit zero.

The vectors are transactions a Sequentia node (elementsregtest) mined: one
issuing input, one atom, no token.
"""
import unittest
from util import *

USE_WITNESS = 0x1      # WALLY_TX_FLAG_USE_WITNESS
USE_ELEMENTS = 0x2     # WALLY_TX_FLAG_USE_ELEMENTS
SIGHASH_DEFAULT = 0x0
SIGHASH_ALL = 0x1
SIGTYPE_SW_V1 = 0x3
EC_FLAG_ECDSA = 0x1
EC_FLAG_SCHNORR = 0x2
PSBT_INIT_PSET = 0x1
PSBT_EXTRACT_NON_FINAL = 0x1

GENESIS = '2ce4e8877c7d9e10387993c9c010918e8d9c45482f1ad65ea6d3db960627af16'
POLICY_ASSET = '01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2'
PREVOUT_VALUE = 200000

# Denomination 8, signed by the node's wallet from a P2WPKH coin.
SIGNED_V0 = {
    'tx': '020000000101f0a77d42f909993ce83c47ab30728a9a7347ccb2d3b1c495731836131b8fe76a0100008000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000001000803010b11f93cd30fae7559317ceeb25708e51f5c769131acae637601b0eb9d49b083010000000000000001001600140cacf212be285fb1016827f537f26e1a7e13c57b01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000000301880016001449f0739e677f0fd26c9a2fa2a416e86125e5b76101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000000bb80000000000000000024730440220444f262f3858b5ef4b7ca6936015d46bad6ea067abe7ab0a672fae1db1b484fc022069146d4c3965d961591eb1ed6cb61f1c41c00496929f89eeb7e1427302ecfe780121032ad332cf1f38c872fc913a2ede489af35d345b93ed2ab5d01351711b85863e8b00000000000000',
    'txid': 'f3da423012cf8e064129dfbbcc250ed4adb672ff59367543d0f946d72a53f497',
    'prevout_script': '001403b11dba1287ed387981c1f40fc0e92e6f840016',
}

# Denomination 8, a key-path P2TR coin, SIGHASH_DEFAULT.
SIGNED_V1 = {
    'tx': '020000000101dec248736a2a62eab11a3bbbdaf7f11cf7b4de847d125b5c352e4b39793c49780100008000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000100080301bd8d07a973dcb814a06a92d6e546a65b3e7875b4ce1929ff3ec93dde40df369a010000000000000001001600149076849a70683e029fa8790f8631874e1d684a6d01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000003018800160014f8f02270577f1c31cca2d30f58b22d9a58ee164401230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000000bb800000000000000000140f7ef0b65e5a2741478d3b0e65af641f0985c2d8e81557737b21025ec8bcf7766c7ee55a741b826141cab26389dfc10b4b2bdd395703efb99818dfffe9010d81600000000000000',
    'txid': '567bd95ebafd98074ae4ebef201e211c2d81490327afbbf93cf816e00efc28b0',
    'prevout_script': '51206d81e0cf6d0eb88bb0432e07e065b11eb2f431a8d5c7277f64eb6c2c76be8085',
}

# Denomination 0, the bytes a PSET input issuing one atom extracts to.
DENOMINATION_0 = {
    'txid': '3c13220110d4a49e11b4ff5d7407aecb7aa0f025d4baac9cd538dbdffa9749c7',
    'prev_txid': 'c3e351dd73583dd0a6317c53dad2f75ae7a68500dcfb8e95a9719396f5b4ac13',
    'prev_vout': 0,
    'outputs': [
        ('014f7e5921a241435dc75d80be1b8845c2e0bbd8dcde94fee38d6a847e69837b38', 1,
         '00140236ed98f221704c61d9241f94ed103de4f58677'),
        (POLICY_ASSET, 197000, '0014e73be39aab23a4524e0b27e8af14f748b98fab82'),
        (POLICY_ASSET, 3000, ''),
    ],
}


def explicit_value(n):
    return '01' + n.to_bytes(8, 'big').hex()


class SequentiaIssuanceTests(unittest.TestCase):

    def setUp(self):
        _, is_elements_build = wally_is_elements_build()
        if not is_elements_build:
            self.skipTest('Elements support is disabled')

    def tx(self, hex_):
        tx_p = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_from_hex(utf8(hex_), USE_WITNESS | USE_ELEMENTS, tx_p))
        return tx_p

    def witness(self, tx, item):
        buf, buf_len = make_cbuffer('00' * 128)
        ret, written = wally_tx_get_input_witness(tx, 0, item, buf, buf_len)
        self.assertEqual(WALLY_OK, ret)
        return buf[:written]

    def txid(self, tx):
        buf, buf_len = make_cbuffer('00' * 32)
        self.assertEqual(WALLY_OK, wally_tx_get_txid(tx, buf, buf_len))
        return h(bytes(reversed(buf))).decode()

    def test_round_trip(self):
        """The denomination byte is read and written back, so the txid is the
        node's."""
        for v in (SIGNED_V0, SIGNED_V1):
            tx = self.tx(v['tx'])
            ret, hex_ = wally_tx_to_hex(tx, USE_WITNESS)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(v['tx'], hex_)
            self.assertEqual(v['txid'], self.txid(tx))

    def test_segwit_v0_sighash_covers_denomination(self):
        """The node wallet's signature verifies over libwally's sighash."""
        tx = self.tx(SIGNED_V0['tx'])
        der_and_type = self.witness(tx, 0)
        pubkey = self.witness(tx, 1)
        self.assertEqual(der_and_type[-1], SIGHASH_ALL)
        sig, sig_len = make_cbuffer('00' * 64)
        der, der_len = make_cbuffer(h(der_and_type[:-1]).decode())
        self.assertEqual(WALLY_OK, wally_ec_sig_from_der(der, der_len, sig, sig_len))
        program = SIGNED_V0['prevout_script'][4:]
        script, script_len = make_cbuffer('76a914' + program + '88ac')
        value, value_len = make_cbuffer(explicit_value(PREVOUT_VALUE))
        msg, msg_len = make_cbuffer('00' * 32)
        self.assertEqual(WALLY_OK, wally_tx_get_elements_signature_hash(
            tx, 0, script, script_len, value, value_len, SIGHASH_ALL, USE_WITNESS,
            msg, msg_len))
        pub, pub_len = make_cbuffer(h(pubkey).decode())
        self.assertEqual(WALLY_OK, wally_ec_sig_verify(pub, pub_len, msg, msg_len,
                                                       EC_FLAG_ECDSA, sig, sig_len))

    def test_taproot_sighash_covers_denomination(self):
        """The key-path signature the node accepted verifies over libwally's
        sighash."""
        tx = self.tx(SIGNED_V1['tx'])
        schnorr = self.witness(tx, 0)
        self.assertEqual(len(schnorr), 64)

        def one(hex_):
            m = pointer(wally_map())
            self.assertEqual(WALLY_OK, wally_map_init_alloc(1, None, m))
            b, b_len = make_cbuffer(hex_)
            self.assertEqual(WALLY_OK, wally_map_add_integer(m, 0, b, b_len))
            return m

        scripts = one(SIGNED_V1['prevout_script'])
        assets = one(POLICY_ASSET)
        values = one(explicit_value(PREVOUT_VALUE))
        genesis, genesis_len = make_cbuffer(GENESIS)
        msg, msg_len = make_cbuffer('00' * 32)
        self.assertEqual(WALLY_OK, wally_tx_get_input_signature_hash(
            tx, 0, scripts, assets, values, None, 0, 0, 0xFFFFFFFF, None, 0,
            genesis, genesis_len, SIGHASH_DEFAULT, SIGTYPE_SW_V1, None, msg, msg_len))
        key, key_len = make_cbuffer(SIGNED_V1['prevout_script'][4:])
        sig, sig_len = make_cbuffer(h(schnorr).decode())
        self.assertEqual(WALLY_OK, wally_ec_sig_verify(key, key_len, msg, msg_len,
                                                       EC_FLAG_SCHNORR, sig, sig_len))

    def test_pset_issuance_without_token(self):
        """A PSET input issuing one atom and no token extracts to the
        transaction the node mined: null token count, denomination 0."""
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 3, 0, PSBT_INIT_PSET, psbt))
        txid, txid_len = make_cbuffer(DENOMINATION_0['prev_txid'])
        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_tx_input_init_alloc(
            txid[::-1], txid_len, DENOMINATION_0['prev_vout'], 0xffffffff, None, 0, None, tx_in))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))
        self.assertEqual(WALLY_OK, wally_psbt_input_set_issuance_amount(psbt.contents.inputs, 1))
        for i, (asset_hex, atoms, spk_hex) in enumerate(DENOMINATION_0['outputs']):
            asset, asset_len = make_cbuffer(asset_hex)
            value, value_len = make_cbuffer(explicit_value(atoms))
            spk, spk_len = make_cbuffer(spk_hex) if spk_hex else (None, 0)
            out = pointer(wally_tx_output())
            self.assertEqual(WALLY_OK, wally_tx_elements_output_init_alloc(
                spk, spk_len, asset, asset_len, value, value_len, None, 0, None, 0, None, 0, out))
            self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, i, 0, out))
        tx = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_psbt_extract(psbt, PSBT_EXTRACT_NON_FINAL, tx))
        self.assertEqual(DENOMINATION_0['txid'], self.txid(tx))


if __name__ == '__main__':
    unittest.main()
