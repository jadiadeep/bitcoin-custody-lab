"""CLI for the bitcoin-custody-lab toolkit.

Usage:
    python -m btc_custody.cli gen-address [--privkey HEX] [--uncompressed]
    python -m btc_custody.cli assess --config examples/custody-config-multisig.json [--json]
"""

from __future__ import annotations

import argparse
import json
import sys

from . import keys
from . import custody


def _cmd_gen_address(args: argparse.Namespace) -> int:
    if args.privkey:
        try:
            priv = bytes.fromhex(args.privkey)
        except ValueError:
            print("error: --privkey must be hex", file=sys.stderr)
            return 2
    else:
        priv = keys.generate()
    try:
        pubkey = keys.privkey_to_pubkey(priv, compressed=not args.uncompressed)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"private key (hex): {priv.hex()}")
    print(f"public key  (hex): {pubkey.hex()}")
    print(f"address (P2PKH)  : {keys.pubkey_to_p2pkh(pubkey)}")
    print(f"WIF              : {keys.privkey_to_wif(priv, compressed=not args.uncompressed)}")
    return 0


def _cmd_assess(args: argparse.Namespace) -> int:
    try:
        with open(args.config, "r", encoding="utf-8") as fh:
            config = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read config: {exc}", file=sys.stderr)
        return 2
    report = custody.assess(config)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(custody.format_text(report), end="")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="btc-custody",
        description="Bitcoin custody-security toolkit: key/address generation "
                    "and custody configuration assessment.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("gen-address", help="Generate a keypair and P2PKH address")
    p_gen.add_argument("--privkey", metavar="HEX",
                       help="Use this 32-byte hex private key instead of generating one")
    p_gen.add_argument("--uncompressed", action="store_true",
                       help="Use uncompressed public key format")
    p_gen.set_defaults(func=_cmd_gen_address)

    p_assess = sub.add_parser("assess", help="Assess a custody configuration")
    p_assess.add_argument("--config", required=True, metavar="FILE",
                          help="Path to a JSON custody config (see examples/)")
    p_assess.add_argument("--json", action="store_true",
                          help="Emit the report as JSON instead of text")
    p_assess.set_defaults(func=_cmd_assess)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
