"""btc_custody: Bitcoin custody-security toolkit (educational)."""

from .keys import (
    generate,
    privkey_to_pubkey,
    privkey_to_address,
    privkey_to_wif,
    pubkey_to_p2pkh,
    hash160,
    b58encode,
)
from .custody import assess, format_text, SCHEMES

__version__ = "0.1.0"

__all__ = [
    "generate",
    "privkey_to_pubkey",
    "privkey_to_address",
    "privkey_to_wif",
    "pubkey_to_p2pkh",
    "hash160",
    "b58encode",
    "assess",
    "format_text",
    "SCHEMES",
    "__version__",
]
