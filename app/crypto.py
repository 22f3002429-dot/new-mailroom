import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .canonical import receipt_signing_bytes


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def import_ed25519_public_key(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("Unsupported public key JWK")
    x = jwk.get("x")
    if not isinstance(x, str) or not x:
        raise ValueError("Missing Ed25519 public key x")
    raw = b64url_decode(x)
    if len(raw) != 32:
        raise ValueError("Invalid Ed25519 public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_receipt_signature(
    public_key: Ed25519PublicKey,
    profile: str,
    evaluation_id: str,
    input_digest: str,
    receipt: dict,
) -> bool:
    signature_b64 = receipt.get("receiptSignature")
    if not isinstance(signature_b64, str) or not signature_b64:
        return False
    try:
        signature = b64url_decode(signature_b64)
        message = receipt_signing_bytes(
            profile, evaluation_id, input_digest, receipt
        )
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False
