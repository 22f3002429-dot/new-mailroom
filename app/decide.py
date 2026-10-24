import re
import uuid
from typing import Any

from .canonical import input_digest
from .llm import decide_batch
from .storage import get_cached_proposal, save_cached_proposal

ALLOWED_ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}

PAYLOAD_KEYS = {
    "create_draft": {"recipient", "referenceId", "status", "template"},
    "update_internal_record": {"field", "sourceEventId", "value"},
    "send_approved_notice": {"referenceId", "status", "template"},
    "request_confirmation": {"claimedSender", "questionCode", "referenceId"},
    "quarantine_item": {"artifactId", "reasonCode"},
    "no_action": {"reasonCode", "referenceId"},
}


class DecisionError(Exception):
    pass


def dossier_fingerprint(dossier: dict) -> str:
    """Cache identity is dossier content, never evaluationId or auditId."""
    return input_digest([dossier])


def collect_line_ids(dossier: dict) -> set[str]:
    ids = set()
    for source in dossier.get("sources", []):
        for line in source.get("lines", []):
            ids.add(line["lineId"])
    return ids


def validate_model_proposal(raw: Any, dossier: dict, allowed_actions: set[str]) -> dict:
    if not isinstance(raw, dict):
        raise DecisionError("Model decision must be an object")

    dossier_id = raw.get("dossierId")
    if dossier_id != dossier["dossierId"]:
        raise DecisionError("Model returned wrong dossierId")

    action = raw.get("action")
    if action not in allowed_actions or action not in ALLOWED_ACTIONS:
        raise DecisionError("Model returned a disallowed action")

    target = raw.get("target")
    payload = raw.get("payload")
    evidence = raw.get("evidence")

    if not isinstance(payload, dict):
        raise DecisionError("payload must be an object")
    if set(payload.keys()) != PAYLOAD_KEYS[action]:
        raise DecisionError("payload fields do not match action schema")

    if action == "no_action":
        if target is not None:
            raise DecisionError("no_action target must be null")
        if payload.get("reasonCode") not in {
            "ALREADY_COMPLETED", "DUPLICATE", "INFORMATIONAL"
        }:
            raise DecisionError("invalid no_action reasonCode")
    else:
        if not isinstance(target, dict) or set(target.keys()) != {"kind", "id"}:
            raise DecisionError("target must contain exactly kind and id")
        if not isinstance(target["kind"], str) or not isinstance(target["id"], str):
            raise DecisionError("target kind/id must be strings")

    expected_targets = {
        "create_draft": "draft_queue",
        "update_internal_record": "case_record",
        "send_approved_notice": "email",
        "request_confirmation": "approval_queue",
        "quarantine_item": "security_queue",
    }
    if action in expected_targets:
        if target["kind"] != expected_targets[action]:
            raise DecisionError("wrong target kind")

    if action == "create_draft" and target["id"] != f"mailbox:{dossier['mailbox']}":
        raise DecisionError("create_draft target must be the dossier mailbox")
    if action == "update_internal_record" and payload.get("field") != "delivery_window":
        raise DecisionError("update_internal_record field must be delivery_window")
    if action == "send_approved_notice" and payload.get("template") != "approved_delivery_notice":
        raise DecisionError("send_approved_notice template is fixed")
    if action == "create_draft" and payload.get("template") != "order_status":
        raise DecisionError("create_draft template is fixed")
    if action == "request_confirmation" and payload.get("questionCode") != "VERIFY_REQUEST":
        raise DecisionError("request_confirmation questionCode is fixed")
    if action == "quarantine_item":
        if target != {"kind": "security_queue", "id": "mailroom"}:
            raise DecisionError("quarantine target is fixed")
        if payload.get("reasonCode") != "INDIRECT_PROMPT_INJECTION":
            raise DecisionError("quarantine reasonCode is fixed")

    if not isinstance(evidence, list) or not evidence:
        raise DecisionError("evidence must be a non-empty array")
    valid_ids = collect_line_ids(dossier)
    seen = set()
    for item in evidence:
        if not isinstance(item, str) or item not in valid_ids:
            raise DecisionError("evidence contains an unknown lineId")
        if item in seen:
            raise DecisionError("evidence contains a duplicate lineId")
        seen.add(item)

    return {
        "dossierId": dossier["dossierId"],
        "callId": raw.get("callId"),
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": list(dict.fromkeys(evidence)),
    }


def new_call_id() -> str:
    return ("mrm-" + uuid.uuid4().hex)[:64]


async def build_proposals(dossiers: list[dict], allowed_actions: list[str]) -> list[dict]:
    allowed = set(allowed_actions)
    proposals = []
    uncached = []
    fingerprints = {}

    for dossier in dossiers:
        fp = dossier_fingerprint(dossier)
        fingerprints[dossier["dossierId"]] = fp
        cached = get_cached_proposal(fp)
        if cached:
            proposals.append(cached)
        else:
            uncached.append(dossier)

    if uncached:
        result = await decide_batch(uncached, sorted(allowed))
        decisions = result.get("decisions") if isinstance(result, dict) else None
        if not isinstance(decisions, list):
            raise DecisionError("Model response missing decisions array")

        by_id = {}
        for item in decisions:
            if isinstance(item, dict) and isinstance(item.get("dossierId"), str):
                by_id[item["dossierId"]] = item

        for dossier in uncached:
            raw = by_id.get(dossier["dossierId"])
            if raw is None:
                raise DecisionError(f"Missing model decision for {dossier['dossierId']}")
            proposal = validate_model_proposal(raw, dossier, allowed)
            if not proposal.get("callId") or not re.fullmatch(
                r"^[A-Za-z0-9._:-]{12,128}$", proposal["callId"]
            ):
                proposal["callId"] = new_call_id()
            save_cached_proposal(fingerprints[dossier["dossierId"]], proposal)
            proposals.append(proposal)

    # Preserve request order and ensure uniqueness.
    final = []
    used_calls = set()
    for dossier in dossiers:
        match = next(
            p for p in proposals if p["dossierId"] == dossier["dossierId"]
        )
        call_id = match["callId"]
        if call_id in used_calls:
            match = dict(match)
            match["callId"] = new_call_id()
            call_id = match["callId"]
        used_calls.add(call_id)
        final.append(match)
    return final
