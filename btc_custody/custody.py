"""Custody configuration assessor.

Takes a description of a Bitcoin custody setup and returns findings mapped to
the STRIDE threat model in CUSTODY_THREAT_MODEL.md. Rules are deliberately
conservative: any single point of total fund loss or compromise is critical.

Expected config shape (see examples/):
    {
      "name": "exchange cold storage",
      "scheme": "multisig-cold-2of3",   # see SCHEMES below
      "key_storage": "hardware-wallet", # software-hot | hsm | hardware-wallet
                                        # paper | custodian
      "signing": "airgapped",           # online | airgapped | hsm-policy
      "backup": "geodistributed",       # none | single-copy | geodistributed
      "key_locations": 3,               # distinct physical sites holding keys
      "operators": 3,                   # people able to participate in signing
      "hot_float_pct": 2                # % of funds kept in hot wallet (0-100)
    }
"""

from __future__ import annotations

SCHEMES = (
    "singlesig-hot",
    "singlesig-cold",
    "multisig-hot-2of3",
    "multisig-cold-2of3",
    "multisig-cold-3of5",
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding(fid, stride, severity, title, detail, remediation):
    return {
        "id": fid,
        "stride": stride,
        "severity": severity,
        "title": title,
        "detail": detail,
        "remediation": remediation,
    }


def assess(config: dict) -> dict:
    """Assess a custody config; returns {"findings": [...], "summary": {...}}."""
    findings = []
    scheme = config.get("scheme", "")
    storage = config.get("key_storage", "")
    signing = config.get("signing", "")
    backup = config.get("backup", "")
    locations = int(config.get("key_locations", 1) or 1)
    operators = int(config.get("operators", 1) or 1)
    hot_pct = float(config.get("hot_float_pct", 0) or 0)

    is_hot = "hot" in scheme
    is_single = scheme.startswith("singlesig")

    # -- CUSTODY-001: single key on a networked host -------------------------
    if scheme == "singlesig-hot":
        findings.append(_finding(
            "CUSTODY-001", "Elevation of privilege", "critical",
            "Single private key on a networked host controls funds",
            "One compromised host (malware, RCE, malicious insider with access) "
            "yields total fund loss. There is no quorum, no second factor, and no "
            "blast-radius limit: the key IS the money.",
            "Move to 2-of-3 multisig with airgapped signing; keep only a small "
            "operational float hot and sweep surplus to cold on a schedule.",
        ))

    # -- CUSTODY-002: key material on internet-connected host ----------------
    if is_hot and storage == "software-hot":
        findings.append(_finding(
            "CUSTODY-002", "Information disclosure", "high",
            "Key material lives in memory/disk of an internet-connected host",
            "Software wallets keep decrypted keys in process memory. Any host "
            "compromise, memory-scraping malware, or unencrypted disk image / "
            "snapshot exfiltrates the key without needing to break any crypto.",
            "Sign inside an HSM with a spend policy (rate limits, allowlists), "
            "or move signing offline and broadcast via a watch-only host.",
        ))

    # -- CUSTODY-003: no backup ---------------------------------------------
    if backup in ("none", "", None):
        findings.append(_finding(
            "CUSTODY-003", "Denial of service", "high",
            "No key backup: loss of key material is irreversible fund loss",
            "Bitcoin has no password reset. Fire, flood, hardware failure, or "
            "accidental deletion of the only key copy destroys the funds just "
            "as thoroughly as theft does.",
            "Create geographically distributed backups (e.g. Shamir-shared seed "
            "across sites); test restoration on a schedule, not just creation.",
        ))
    elif backup == "single-copy":
        findings.append(_finding(
            "CUSTODY-004", "Denial of service", "medium",
            "Single backup copy shares fate with the primary",
            "One copy in one location does not survive site-level events and is "
            "a single theft target that bypasses operational controls.",
            "Distribute backups across at least two independent physical sites.",
        ))

    # -- CUSTODY-005: single operator can move funds -------------------------
    if is_single and operators <= 1:
        findings.append(_finding(
            "CUSTODY-005", "Repudiation", "high",
            "One operator can move funds with no independent check",
            "Unilateral spend capability means fraud or coercion of a single "
            "person is sufficient, and post-incident attribution is weak.",
            "Require M-of-N authorization across operators (multisig quorum "
            "spanning people, not just keys) plus dual-control procedures.",
        ))

    # -- CUSTODY-006: quorum keys co-located ---------------------------------
    if scheme.startswith("multisig"):
        quorum = 2 if "2of3" in scheme else 3
        if locations < quorum:
            findings.append(_finding(
                "CUSTODY-006", "Tampering", "medium",
                "Quorum-reaching keys stored in fewer locations than the quorum",
                f"With keys in {locations} site(s) and a {quorum}-key quorum, a "
                "single physical event (or one coerced insider at one site) can "
                "assemble signing power.",
                "Distribute each key to its own physical site under separate "
                "access control; no site should ever hold a quorum.",
            ))

    # -- CUSTODY-007: cold scheme signed on networked device -----------------
    if not is_hot and signing == "online":
        findings.append(_finding(
            "CUSTODY-007", "Elevation of privilege", "medium",
            "'Cold' keys signed on a networked device",
            "If the signing device is online at signing time, the cold/warm "
            "distinction is marketing: key material is exposed to the network.",
            "Sign via airgapped flow (PSBT over QR / removable media) on a "
            "device that never touches a network.",
        ))

    # -- CUSTODY-008: oversized hot float ------------------------------------
    if hot_pct > 5:
        findings.append(_finding(
            "CUSTODY-008", "Tampering", "medium",
            f"Hot wallet holds {hot_pct:g}% of funds — large blast radius",
            "Hot wallets are the highest-exposure component. Keeping more than "
            "a small operational float hot multiplies the payoff of the "
            "CUSTODY-001/002 attack paths.",
            "Cap the hot float (common practice: <=5% or one day of outflows) "
            "with automated sweeping to cold.",
        ))

    # -- CUSTODY-009: no HSM anywhere ----------------------------------------
    if storage not in ("hsm",) and is_hot:
        findings.append(_finding(
            "CUSTODY-009", "Information disclosure", "low",
            "No HSM in the signing path",
            "Without hardware-backed signing, key material is only as safe as "
            "the host OS. HSMs add tamper-evident storage and policy-enforced "
            "signing (rate limits, destination allowlists).",
            "Evaluate HSM-backed signing for the hot wallet with spend policies.",
        ))

    # -- CUSTODY-010: custodian without proof --------------------------------
    if storage == "custodian":
        findings.append(_finding(
            "CUSTODY-010", "Spoofing", "medium",
            "Third-party custodian: trust is asserted, not verified",
            "Funds are only as safe as the custodian's controls, which you "
            "cannot directly observe. Counterparty failure is a distinct risk "
            "from key compromise.",
            "Require SOC 2 Type II / ISO 27001 evidence, proof-of-reserves, "
            "contractual SLAs, and an exit plan (key export / migration).",
        ))

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "findings": findings,
        "summary": {
            "config": config.get("name", "unnamed"),
            "total_findings": len(findings),
            "by_severity": counts,
            "highest_severity": findings[0]["severity"] if findings else None,
        },
    }


def format_text(report: dict) -> str:
    """Human-readable rendering of an assess() report."""
    lines = []
    s = report["summary"]
    lines.append(f"Custody assessment: {s['config']}")
    lines.append(f"Findings: {s['total_findings']} " +
                 (f"(highest: {s['highest_severity']})" if s["highest_severity"] else "(clean)"))
    lines.append("")
    for f in report["findings"]:
        lines.append(f"[{f['severity'].upper()}] {f['id']} ({f['stride']})")
        lines.append(f"  {f['title']}")
        lines.append(f"  Detail: {f['detail']}")
        lines.append(f"  Fix: {f['remediation']}")
        lines.append("")
    if not report["findings"]:
        lines.append("No findings: configuration meets the baseline checks.")
    return "\n".join(lines).rstrip() + "\n"
