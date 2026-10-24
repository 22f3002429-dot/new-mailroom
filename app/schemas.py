import re
from typing import Any

PROFILE = "ga5-mailroom-action-gate/v2"
ALLOWED_ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}
CALL_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{12,128}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ContractError(Exception):
    pass


def require_dict(value: Any, name: str) -> dict:
    if not isinstance(value, dict):
        raise ContractError(f"{name} must be an object")
    return value


def require_str(value: Any, name: str, max_len: int = 100000) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{name} must be a non-empty string")
    if len(value) > max_len:
        raise ContractError(f"{name} is too long")
    return value


def validate_propose(body: dict) -> dict:
    body = require_dict(body, "body")
    if body.get("profile") != PROFILE:
        raise ContractError("Invalid profile")
    if body.get("operation") != "propose":
        raise ContractError("operation must be propose")

    evaluation_id = require_str(body.get("evaluationId"), "evaluationId", 256)
    verifier = require_dict(body.get("receiptVerifier"), "receiptVerifier")
    if verifier.get("algorithm") != "Ed25519":
        raise ContractError("receiptVerifier.algorithm must be Ed25519")
    jwk = require_dict(verifier.get("publicKeyJwk"), "publicKeyJwk")

    corpus = require_dict(body.get("corpus"), "corpus")
    require_str(corpus.get("coreId"), "corpus.coreId", 256)
    require_str(corpus.get("auditId"), "corpus.auditId", 256)
    if not isinstance(corpus.get("stableCount"), int):
        raise ContractError("corpus.stableCount must be integer")
    if not isinstance(corpus.get("freshCount"), int):
        raise ContractError("corpus.freshCount must be integer")

    allowed = body.get("allowedActions")
    if not isinstance(allowed, list) or not allowed or not set(allowed).issubset(ALLOWED_ACTIONS):
        raise ContractError("allowedActions is invalid")

    dossiers = body.get("dossiers")
    if not isinstance(dossiers, list) or not dossiers:
        raise ContractError("dossiers must be a non-empty array")

    seen = set()
    for d in dossiers:
        d = require_dict(d, "dossier")
        dossier_id = require_str(d.get("dossierId"), "dossierId", 256)
        if dossier_id in seen:
            raise ContractError("duplicate dossierId")
        seen.add(dossier_id)

        if d.get("partition") not in {"stable_core", "fresh_audit"}:
            raise ContractError("invalid dossier partition")
        require_str(d.get("receivedAt"), "receivedAt", 128)
        require_str(d.get("mailbox"), "mailbox", 512)
        require_str(d.get("objective"), "objective", 20000)

        sources = d.get("sources")
        if not isinstance(sources, list) or not sources:
            raise ContractError("dossier.sources must be non-empty")
        source_ids = set()
        for s in sources:
            s = require_dict(s, "source")
            source_id = require_str(s.get("sourceId"), "sourceId", 256)
            if source_id in source_ids:
                raise ContractError("duplicate sourceId")
            source_ids.add(source_id)
            require_str(s.get("kind"), "source.kind", 128)
            require_str(s.get("provenance"), "source.provenance", 512)
            require_str(s.get("title"), "source.title", 1024)
            lines = s.get("lines")
            if not isinstance(lines, list) or not lines:
                raise ContractError("source.lines must be non-empty")
            line_ids = set()
            for line in lines:
                line = require_dict(line, "line")
                line_id = require_str(line.get("lineId"), "lineId", 256)
                if line_id in line_ids:
                    raise ContractError("duplicate lineId")
                line_ids.add(line_id)
                require_str(line.get("text"), "line.text", 20000)

    return {
        "evaluationId": evaluation_id,
        "receiptVerifier": verifier,
        "corpus": corpus,
        "allowedActions": allowed,
        "dossiers": dossiers,
    }


def validate_commit(body: dict) -> dict:
    body = require_dict(body, "body")
    if body.get("profile") != PROFILE:
        raise ContractError("Invalid profile")
    if body.get("operation") != "commit":
        raise ContractError("operation must be commit")

    evaluation_id = require_str(body.get("evaluationId"), "evaluationId", 256)
    input_digest = require_str(body.get("inputDigest"), "inputDigest", 64)
    if not HEX64_RE.fullmatch(input_digest):
        raise ContractError("inputDigest must be lowercase SHA-256 hex")

    receipts = body.get("receipts")
    if not isinstance(receipts, list) or not receipts:
        raise ContractError("receipts must be a non-empty array")

    seen_dossiers = set()
    seen_receipt_ids = set()
    for r in receipts:
        r = require_dict(r, "receipt")
        dossier_id = require_str(r.get("dossierId"), "dossierId", 256)
        if dossier_id in seen_dossiers:
            raise ContractError("duplicate receipt dossierId")
        seen_dossiers.add(dossier_id)

        require_str(r.get("callId"), "callId", 128)
        if r.get("action") not in ALLOWED_ACTIONS:
            raise ContractError("invalid receipt action")
        if not isinstance(r.get("accepted"), bool):
            raise ContractError("receipt.accepted must be boolean")
        pd = require_str(r.get("proposalDigest"), "proposalDigest", 64)
        if not HEX64_RE.fullmatch(pd):
            raise ContractError("proposalDigest must be lowercase SHA-256 hex")
        receipt_id = require_str(r.get("receiptId"), "receiptId", 256)
        if receipt_id in seen_receipt_ids:
            raise ContractError("duplicate receiptId")
        seen_receipt_ids.add(receipt_id)
        require_str(r.get("receiptSignature"), "receiptSignature", 4096)

    return {
        "evaluationId": evaluation_id,
        "inputDigest": input_digest,
        "receipts": receipts,
    }
