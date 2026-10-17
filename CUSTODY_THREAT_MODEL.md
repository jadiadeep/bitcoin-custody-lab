# Custody Threat Model — Exchange Hot/Cold Wallet Architecture

Method: STRIDE. Scope: an exchange holding customer BTC across an online hot
wallet (operational float) and airgapped 2-of-3 multisig cold storage.
Out of scope: consensus attacks, exchange trading engine, fiat rails.

## 1. Architecture under review

```
[Internet] --> [Hot signing host] --(sweep tx)--> [Bitcoin network]
                    ^  (watch-only)
                    |
              [Airgapped signing device] <--QR/PSBT--> [Coordinator laptop]
                    |
        [Cold key A: HSM/site 1] [Cold key B: HW wallet/site 2] [Cold key C: paper/site 3]
```

- **Hot wallet:** 2-of-3 multisig where one key is HSM-backed on the signing
  host, one key with the on-call operator (hardware wallet), one key in a
  warm HSM. Holds <=5% of funds / ~24h of expected outflows. Automated
  sweeps move surplus to cold.
- **Cold storage:** 2-of-3 multisig, keys on three separate hardware wallets
  in three physical sites, signing via airgapped PSBT over QR codes.
  No cold key has ever touched a networked device.

## 2. Assets

| # | Asset | Why it matters |
|---|---|---|
| A1 | Hot wallet private key material / HSM signing capability | Direct spend authority over the float |
| A2 | Cold key shares (3 sites) | Any 2 = total fund control |
| A3 | Unsigned/signed PSBTs in flight | Tamper target between coordinator and signer |
| A4 | xpubs / watch-only wallets | Privacy + targeting intel if leaked |
| A5 | Backup seeds / Shamir shares | Equivalent to the keys themselves |
| A6 | Operator credentials & MFA factors | Path to impersonating a quorum member |
| A7 | Audit log of signing ceremonies | Detecting and attributing misuse |

## 3. Trust boundaries

1. Internet ↔ hot signing host (highest exposure).
2. Hot environment ↔ cold environment (must be airgapped; QR/PSBT only).
3. Between the three cold sites (no site holds a quorum).
4. Personnel ↔ systems (operators are inside the trust boundary by design —
   the model assumes they can be coerced or go rogue).

## 4. Threats by STRIDE category

### Spoofing
- **S1 — Fake coordinator software.** Attacker supplies a trojaned PSBT
  coordinator to the signing ceremony; it displays one address while signing
  another. *Mitigation:* verify receive/change addresses on the hardware
  wallet's own trusted display; coordinator built reproducibly from pinned
  source.
- **S2 — Impersonated operator.** Attacker with stolen credentials + SIM-swapped
  MFA joins a signing ceremony as a quorum member. *Mitigation:* FIDO2
  hardware keys for operator auth; quorum requires two *distinct* operators,
  verified out-of-band for large moves.

### Tampering
- **T1 — Destination address swap.** Malware on the coordinator alters the
  PSBT output address. *Mitigation:* airgapped signing device shows the full
  destination address; operator verifies character-by-character for
  above-threshold amounts; address allowlisting for routine sweeps.
- **T2 — Co-located quorum keys.** If two cold keys end up in one safe, a
  single physical breach assembles a quorum. *Mitigation:* enforced key-location
  inventory; no site ever holds >= quorum; surprise audits. (Checked by
  `CUSTODY-006` in the assessor.)

### Repudiation
- **R1 — Unilateral insider spend.** A single operator with sole signing power
  moves funds and claims compromise. *Mitigation:* M-of-N across *people*,
  dual-control for amounts over threshold, append-only tamper-evident log of
  every ceremony (who, what, when, which device).
- **R2 — Disputed ceremony.** "I never approved that transaction."
  *Mitigation:* each quorum member signs an approval record with their
  operator key; log shipped to immutable storage.

### Information disclosure
- **I1 — Hot key exfiltration.** Memory-scraping malware or a disk snapshot
  lifts the hot key. *Mitigation:* HSM-backed signing so the key never exists
  in host memory; if software signing is unavoidable, cap the float and rotate
  keys on a schedule. (Checked by `CUSTODY-002`.)
- **I2 — xpub leak.** Leaked extended public keys expose the full wallet
  transaction graph to chain analysis. *Mitigation:* need-to-know distribution
  of xpubs; separate xpub per cold site where the scheme allows.

### Denial of service
- **D1 — Key loss.** Fire/flood/deletion destroys the only copy of a key or
  seed; funds are cryptographically unrecoverable — Bitcoin has no password
  reset. *Mitigation:* geodistributed backups (Shamir-shared seeds across
  sites); *tested* restores, not just tested backups. (Checked by
  `CUSTODY-003`/`CUSTODY-004`.)
- **D2 — HSM/operator unavailability.** Sole HSM fails or sole operator is
  unreachable during an incident requiring movement. *Mitigation:* 2-of-3
  tolerates one failure by design; documented break-glass with a fourth
  geographically separated recovery path.

### Elevation of privilege
- **E1 — Hot host compromise = total float loss.** Any RCE on the signing host
  can request signatures up to the HSM policy limit. *Mitigation:* HSM spend
  policies (per-tx caps, destination allowlists, velocity limits); anomaly
  alerting on signing rate; minimal float. (Checked by `CUSTODY-001`.)
- **E2 — Supply-chain: backdoored hardware wallet.** A compromised device
  exfiltrates the seed at setup. *Mitigation:* buy from manufacturer only,
  verify attestation/firmware hashes, initialize with dice-generated entropy,
  never use a pre-seeded device.

## 5. Residual risks (accepted, monitored)

- A state-level actor coercing 2 of 3 key holders simultaneously. Mitigated by
  geographic/jurisdictional separation; cannot be engineered away.
- Cryptographic break of secp256k1 or SHA-256 (outside this model's scope;
  would be an industry-wide event).
- QR-code based exfiltration from the airgapped signer via a compromised
  coordinator camera path — accepted; mitigated by ceremony observation.

## 6. How the assessor maps to this model

Each `CUSTODY-*` finding in `btc_custody/custody.py` references one of the
threats above (e.g. `CUSTODY-001` ↔ E1, `CUSTODY-003` ↔ D1). The assessor is a
baseline checklist, not a substitute for this analysis: it catches
misconfigurations, not novel attack paths.
