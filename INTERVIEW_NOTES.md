# Interview Notes — btc-custody-lab

Study these cold. Each answer is the *complete* answer — if you can say it
without notes, you can defend the project.

**1. Why compressed public keys instead of uncompressed?**
A compressed key is 33 bytes (x-coordinate + one parity byte for y) versus 65
bytes uncompressed, with identical security — the full point is recoverable
because y² = x³ + 7 has only two solutions and the prefix byte (0x02/0x03)
selects the even/odd one. Smaller keys mean smaller transactions and lower
fees, which is why everything modern uses compressed.

**2. What does the Base58Check checksum actually protect against?**
The last 4 bytes are the first 4 bytes of double-SHA256 over the payload, so
any typo or transcription error is caught with probability 1 − 2⁻³². It does
*not* protect against sending to a wrong-but-valid address — that's what
address verification on a trusted display is for (threat T1 in my model).

**3. Why is a private key "just a number," and why does generation matter?**
The private key is a scalar k in [1, n−1] multiplied by the generator point G
to get the public key; security is the elliptic-curve discrete-log problem —
recovering k from k·G is infeasible. So the *only* secret is that k was picked
uniformly at random, which is why I used the `secrets` module (CSPRNG) and
reject k = 0 or k ≥ n.

**4. Why RIPEMD-160(SHA-256(pubkey)) instead of just SHA-256?**
Two reasons: it compresses the address payload to 20 bytes (shorter
addresses), and it's defense in depth — an attacker would have to break *both*
hash functions to derive a public key from an address. It's a deliberate
Bitcoin design choice, not an arbitrary one.

**5. Why is 2-of-3 multisig better than a single key for cold storage?**
No single point of failure in either direction: compromising or losing *one*
key neither grants fund access nor blocks legitimate spending. The quorum can
also span people and sites, so one coerced insider or one physical breach is
insufficient — that's the core of threats E1, T2, and R1 in my model.

**6. What was the top finding in your STRIDE model?**
A single private key on a networked host (E1): one compromised machine means
total, immediate fund loss — the key *is* the money, there's no account to
freeze and no fraud department to call. That's why the model pushes to
HSM-backed signing, minimal hot floats with auto-sweeping, and airgapped cold
quorums.

**7. What's the difference between your hot and cold wallet designs?**
The hot wallet signs on (or via) a networked host for operational speed but
holds only a capped float; the cold wallet's keys have never touched a
networked device and sign via airgapped PSBTs carried over QR codes. The
security boundary isn't "hot vs cold" as labels — it's whether key material
is ever exposed to a network, which my assessor checks as CUSTODY-007.

**8. How does your assessor decide severity?**
Critical = a single point of *total* fund loss or compromise with no second
factor (singlesig-hot). High = likely loss path needing one more failure
(no backup, unilateral operator). Medium/low = defense-in-depth gaps
(co-located quorum keys, no HSM). Every rule maps to a STRIDE category and
names a concrete remediation.

**9. What was the hardest bug you hit building this?**
My hand-rolled RIPEMD-160 failed the test vectors. Differential debugging
against OpenSSL showed I'd dropped the `+ E` feedforward in the compression
step — the spec's step is `T = rol(A + f(B,C,D) + X + K, s) + E`, and my first
version omitted the `+ E`. It's exactly the kind of subtle, silent bug that
test vectors exist to catch, and why I'd never hand-roll crypto for real
funds.

**10. What would you change before this touched real money?**
Everything about the crypto handling: replace hand-rolled secp256k1 and
RIPEMD-160 with audited libraries (e.g. libsecp256k1), sign inside HSMs with
spend policies, run formal key ceremonies with independent witnesses, validate
the whole flow on testnet/regtest first, and get the ceremony procedures —
not just the code — reviewed. The code here proves understanding; production
needs assurance.
