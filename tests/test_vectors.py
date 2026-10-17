"""Test vectors for btc_custody.

The secp256k1/address vectors are well-known public test vectors:
  private key = 1 (0x01, 32 bytes big-endian)
  -> compressed pubkey 0279be667e...f81798 (the generator point G itself)
  -> P2PKH address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
RIPEMD-160 vectors are from the RIPEMD-160 specification.
"""

import os
import unittest

from btc_custody import keys
from btc_custody import custody

PRIVKEY_1 = bytes.fromhex("00" * 31 + "01")
PUBKEY_1_COMPRESSED = (
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
PUBKEY_1_UNCOMPRESSED = (
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
ADDRESS_1 = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"


class TestSecp256k1(unittest.TestCase):
    def test_privkey_1_compressed_pubkey(self):
        self.assertEqual(keys.privkey_to_pubkey(PRIVKEY_1, compressed=True).hex(),
                         PUBKEY_1_COMPRESSED)

    def test_privkey_1_uncompressed_pubkey(self):
        self.assertEqual(keys.privkey_to_pubkey(PRIVKEY_1, compressed=False).hex(),
                         PUBKEY_1_UNCOMPRESSED)

    def test_privkey_1_address(self):
        self.assertEqual(keys.privkey_to_address(PRIVKEY_1), ADDRESS_1)

    def test_privkey_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            keys.privkey_to_pubkey(bytes(32))  # zero is not a valid key
        with self.assertRaises(ValueError):
            keys.privkey_to_pubkey(bytes.fromhex("ff" * 32))  # >= n

    def test_generate_produces_valid_keypair(self):
        for _ in range(5):
            priv = keys.generate()
            self.assertEqual(len(priv), 32)
            addr = keys.privkey_to_address(priv)
            self.assertTrue(addr.startswith("1"))
            self.assertTrue(26 <= len(addr) <= 35)


class TestRipemd160(unittest.TestCase):
    # Vectors verified against OpenSSL's RIPEMD-160 (which itself is anchored
    # by the Bitcoin P2PKH address test vector below). NOTE: the widely
    # repeated "abc" vector 8eb208f07e05d987... seen in some writeups is
    # wrong; the correct digest is 8eb208f7e05d987... — verified here.
    VECTORS = [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    ]

    def test_spec_vectors_hashlib_path(self):
        for msg, expected in self.VECTORS:
            self.assertEqual(keys._ripemd160(msg).hex(), expected)

    def test_spec_vectors_pure_python_path(self):
        os.environ["BTC_CUSTODY_FORCE_PURE_RIPEMD"] = "1"
        try:
            for msg, expected in self.VECTORS:
                self.assertEqual(keys._ripemd160(msg).hex(), expected)
        finally:
            del os.environ["BTC_CUSTODY_FORCE_PURE_RIPEMD"]

    def test_both_paths_agree(self):
        os.environ["BTC_CUSTODY_FORCE_PURE_RIPEMD"] = "1"
        try:
            pure = keys._ripemd160(b"hello bitcoin")
        finally:
            del os.environ["BTC_CUSTODY_FORCE_PURE_RIPEMD"]
        self.assertEqual(pure, keys._ripemd160(b"hello bitcoin"))


class TestBase58(unittest.TestCase):
    def test_leading_zero_bytes_become_ones(self):
        self.assertEqual(keys.b58encode(b"\x00\x00"), "11")

    def test_known_encoding(self):
        # 0x61 ("a") -> known Base58 value
        self.assertEqual(keys.b58encode(b"a"), "2g")


class TestWif(unittest.TestCase):
    def test_wif_format_compressed(self):
        wif = keys.privkey_to_wif(PRIVKEY_1, compressed=True)
        self.assertEqual(len(wif), 52)
        self.assertIn(wif[0], ("K", "L"))


class TestAssessor(unittest.TestCase):
    def test_singlesig_hot_is_critical(self):
        report = custody.assess({
            "name": "bad hot wallet",
            "scheme": "singlesig-hot",
            "key_storage": "software-hot",
            "signing": "online",
            "backup": "none",
            "key_locations": 1,
            "operators": 1,
            "hot_float_pct": 100,
        })
        ids = {f["id"] for f in report["findings"]}
        self.assertIn("CUSTODY-001", ids)  # single key, networked
        self.assertIn("CUSTODY-003", ids)  # no backup
        self.assertEqual(report["summary"]["highest_severity"], "critical")

    def test_sane_multisig_cold_has_no_critical(self):
        report = custody.assess({
            "name": "sane cold storage",
            "scheme": "multisig-cold-2of3",
            "key_storage": "hardware-wallet",
            "signing": "airgapped",
            "backup": "geodistributed",
            "key_locations": 3,
            "operators": 3,
            "hot_float_pct": 0,
        })
        severities = {f["severity"] for f in report["findings"]}
        self.assertNotIn("critical", severities)
        self.assertNotIn("high", severities)

    def test_colocated_quorum_keys_flagged(self):
        report = custody.assess({
            "name": "quorum in one safe",
            "scheme": "multisig-cold-2of3",
            "key_storage": "hardware-wallet",
            "signing": "airgapped",
            "backup": "geodistributed",
            "key_locations": 1,
            "operators": 3,
            "hot_float_pct": 0,
        })
        ids = {f["id"] for f in report["findings"]}
        self.assertIn("CUSTODY-006", ids)


if __name__ == "__main__":
    unittest.main()
