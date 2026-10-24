import json
import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from .canonical import input_digest, proposal_digest
from .crypto import import_ed25519_public_key, verify_receipt_signature
from .decide import build_proposals
from .schemas import ContractError, PROFILE, validate_commit, validate_propose
from .storage import (
    get_evaluation,
    get_outcomes,
    get_proposal,
    get_proposals,
    init_db,
    receipt_exists,
    save_evaluation,
    save_outcome,
    save_proposals,
    save_receipt,
)

load_dotenv()
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "2000000"))

app = FastAPI(title="Safe AI Mailroom Agent", version="1.0.0")
init_db()


def json_error(status_code: int, message: str):
    return JSONResponse(
        status_code=status_code,
        content={"error": message},
        media_type="application/json",
    )


@app.get("/health")
async def health():
    return {"status": "ok", "profile": PROFILE}


@app.post("/")
async def mailroom(request: Request):
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        return json_error(413, "Request body too large")

    try:
        body = json.loads(raw)
    except Exception:
        return json_error(400, "Invalid JSON")

    if not isinstance(body, dict):
        return json_error(400, "Request body must be an object")

    operation = body.get("operation")
    try:
        if operation == "propose":
            return await handle_propose(body)
        if operation == "commit":
            return await handle_commit(body)
        return json_error(400, "Unknown operation")
    except ContractError as exc:
        return json_error(422, str(exc))
    except Exception as exc:
        return json_error(500, f"Internal error: {type(exc).__name__}")


async def handle_propose(body: dict):
    data = validate_propose(body)
    evaluation_id = data["evaluationId"]
    dossiers = data["dossiers"]
    digest = input_digest(dossiers)

    existing = get_evaluation(evaluation_id)
    if existing:
        if existing["input_digest"] != digest:
            return json_error(409, "evaluationId reused with changed content")

        prior = get_proposals(evaluation_id)
        if prior:
            return semantic_propose_response(
                evaluation_id, digest, [json.loads(p["proposal_json"]) for p in prior]
            )
    else:
        save_evaluation(evaluation_id, digest, data["receiptVerifier"])

    proposals = await build_proposals(dossiers, data["allowedActions"])
    digests = {p["dossierId"]: proposal_digest(p) for p in proposals}
    save_proposals(evaluation_id, proposals, digests)

    return semantic_propose_response(evaluation_id, digest, proposals)


def semantic_propose_response(evaluation_id: str, digest: str, proposals: list[dict]):
    return JSONResponse(
        status_code=200,
        content={
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "status": "awaiting_receipts",
            "inputDigest": digest,
            "proposals": proposals,
        },
        media_type="application/json",
    )


async def handle_commit(body: dict):
    data = validate_commit(body)
    evaluation_id = data["evaluationId"]
    supplied_digest = data["inputDigest"]

    evaluation = get_evaluation(evaluation_id)
    if not evaluation:
        return json_error(404, "Unknown evaluationId")
    if evaluation["input_digest"] != supplied_digest:
        return json_error(409, "inputDigest does not match stored evaluation")

    stored = get_proposals(evaluation_id)
    stored_by_dossier = {p["dossierId"]: p for p in stored}
    if len(stored_by_dossier) != len(data["receipts"]):
        return json_error(422, "Receipt count does not match proposals")

    # Verify every receipt before recording any effect.
    try:
        public_key = import_ed25519_public_key(
            json.loads(evaluation["verifier_json"])["publicKeyJwk"]
        )
    except Exception:
        return json_error(500, "Stored verifier key is invalid")

    verified = []
    for receipt in data["receipts"]:
        dossier_id = receipt["dossierId"]
        proposal_row = stored_by_dossier.get(dossier_id)
        if not proposal_row:
            return json_error(422, f"No persisted proposal for dossier {dossier_id}")

        stored_proposal = json.loads(proposal_row["proposal_json"])
        if receipt["callId"] != stored_proposal["callId"]:
            return json_error(422, "Receipt callId does not match proposal")
        if receipt["action"] != stored_proposal["action"]:
            return json_error(422, "Receipt action does not match proposal")
        if receipt["proposalDigest"] != proposal_row["proposal_digest"]:
            return json_error(422, "Receipt proposalDigest does not match proposal")

        if receipt_exists(evaluation_id, receipt["receiptId"]):
            return json_error(409, "Duplicate receiptId")

        ok = verify_receipt_signature(
            public_key,
            PROFILE,
            evaluation_id,
            supplied_digest,
            receipt,
        )
        if not ok:
            return json_error(422, "Invalid receipt signature")

        verified.append((receipt, stored_proposal, proposal_row["proposal_digest"]))

    # Persist receipts and terminal outcomes only after all signatures verify.
    outcomes = []
    for receipt, stored_proposal, digest_value in verified:
        save_receipt(evaluation_id, receipt)
        outcome = {
            "dossierId": receipt["dossierId"],
            "callId": receipt["callId"],
            "action": receipt["action"],
            "proposalDigest": digest_value,
            "receiptId": receipt["receiptId"],
            "status": "executed" if receipt["accepted"] is True else "rejected",
        }
        save_outcome(evaluation_id, outcome)
        outcomes.append(outcome)

    # Exact replay returns the same terminal semantic result.
    existing_outcomes = get_outcomes(evaluation_id)
    if existing_outcomes:
        outcomes = existing_outcomes

    return JSONResponse(
        status_code=200,
        content={
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "status": "completed",
            "inputDigest": supplied_digest,
            "outcomes": outcomes,
        },
        media_type="application/json",
    )
