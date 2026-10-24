import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Recursively key-sorted, compact JSON encoded as UTF-8."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def input_digest(dossiers: list[dict]) -> str:
    """SHA-256 over UTF-8 bytes of dossiers in recursively key-sorted compact JSON."""
    return sha256_hex(dossiers)


def normalized_proposal(p: dict) -> dict:
    """Keep only digest-relevant proposal fields; sort evidence."""
    evidence = sorted(set(p.get("evidence") or []))
    return {
        "dossierId": p["dossierId"],
        "callId": p["callId"],
        "action": p["action"],
        "target": p.get("target"),
        "payload": p.get("payload"),
        "evidence": evidence,
    }


def proposal_digest(p: dict) -> str:
    return sha256_hex(normalized_proposal(p))


def receipt_signing_bytes(
    profile: str,
    evaluation_id: str,
    input_digest_value: str,
    receipt: dict,
) -> bytes:
    inner = {
        "dossierId": receipt["dossierId"],
        "callId": receipt["callId"],
        "action": receipt["action"],
        "accepted": receipt["accepted"],
        "proposalDigest": receipt["proposalDigest"],
        "receiptId": receipt["receiptId"],
    }
    value = {
        "profile": profile,
        "evaluationId": evaluation_id,
        "inputDigest": input_digest_value,
        "receipt": inner,
    }
    return canonical_json(value)
