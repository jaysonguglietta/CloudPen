import base64
import datetime
import hmac
import json
import os
import re
import time

import boto3

_kms = boto3.client("kms")
_secrets = boto3.client("secretsmanager")
_cached_token = None
_cached_token_at = 0


def lambda_handler(event, _context):
    try:
        if event.get("requestContext", {}).get("http", {}).get("method") != "POST":
            return _response(405, "method_not_allowed")
        headers = {str(key).lower(): str(value) for key, value in (event.get("headers") or {}).items()}
        authorization = headers.get("authorization", "")
        expected = _signer_token()
        supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
            return _response(401, "unauthorized")
        if headers.get("x-cloudpen-signer-protocol") != "cloudpen.signed-artifact.v2":
            return _response(400, "protocol_mismatch")
        raw_body = event.get("body") or ""
        if event.get("isBase64Encoded"):
            raw_body = base64.b64decode(raw_body, validate=True).decode("utf-8")
        if len(raw_body.encode("utf-8")) > 8192:
            return _response(413, "body_too_large")
        body = json.loads(raw_body)
        if set(body) != {"algorithm", "keyId", "message"}:
            return _response(400, "invalid_fields")
        if body["algorithm"] != "PS256" or body["keyId"] != os.environ["EXPECTED_KEY_ID"]:
            return _response(400, "signing_scope_mismatch")
        message = _decode_base64url(body["message"])
        if len(message) < 32 or len(message) > 4096:
            return _response(400, "invalid_message_length")
        _validate_envelope(message)
        result = _kms.sign(
            KeyId=os.environ["KMS_KEY_ID"], Message=message, MessageType="RAW",
            SigningAlgorithm="RSASSA_PSS_SHA_256",
        )
        signature = base64.urlsafe_b64encode(result["Signature"]).decode("ascii").rstrip("=")
        return {"statusCode": 200, "headers": {"content-type": "application/json", "cache-control": "no-store"},
                "body": json.dumps({"signature": signature}, separators=(",", ":"))}
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        return _response(400, "invalid_request")
    except Exception as error:
        print(json.dumps({"schema": "cloudpen.signer-error.v1", "error": type(error).__name__}))
        return _response(503, "signer_unavailable")


def _signer_token():
    global _cached_token, _cached_token_at
    if _cached_token is None or time.monotonic() - _cached_token_at > 300:
        value = _secrets.get_secret_value(SecretId=os.environ["SIGNER_TOKEN_SECRET_ARN"])["SecretString"]
        if len(value) < 32:
            raise ValueError("invalid signer credential")
        _cached_token = value
        _cached_token_at = time.monotonic()
    return _cached_token


def _decode_base64url(value):
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if not isinstance(value, str) or not value or any(character not in allowed for character in value):
        raise ValueError("invalid base64url")
    return base64.b64decode(value.replace("-", "+").replace("_", "/") + "=" * (-len(value) % 4), validate=True)


def _validate_envelope(message):
    envelope = json.loads(message.decode("utf-8"))
    expected_fields = {
        "algorithm", "audience", "domain", "expiresAt", "issuedAt", "keyId", "nonce",
        "payloadDigest", "protocolVersion", "schema", "workspaceId",
    }
    if not isinstance(envelope, dict) or set(envelope) != expected_fields:
        raise ValueError("invalid envelope fields")
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if not hmac.compare_digest(message, canonical):
        raise ValueError("noncanonical envelope")
    audiences = {
        "cloudpen.plan.v2": "cloudpen-runner.v1",
        "cloudpen.approval.v2": "cloudpen-runner.v1",
        "cloudpen.guardrails.v2": "cloudpen-runner.v1",
        "cloudpen.evidence.v2": "cloudpen-evidence-verifier.v1",
        "cloudpen.assessment.v2": "cloudpen-assessment-verifier.v1",
        "cloudpen.audit-anchor.v2": "cloudpen-audit-verifier.v1",
        "cloudpen.backup-manifest.v2": "cloudpen-backup-verifier.v1",
    }
    if envelope["schema"] != "cloudpen.signed-artifact.v2" or envelope["protocolVersion"] != 2:
        raise ValueError("protocol mismatch")
    if envelope["algorithm"] != "PS256" or envelope["keyId"] != os.environ["EXPECTED_KEY_ID"]:
        raise ValueError("key or algorithm mismatch")
    if audiences.get(envelope["domain"]) != envelope["audience"]:
        raise ValueError("domain audience mismatch")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}[a-z0-9]", envelope["workspaceId"]):
        raise ValueError("invalid workspace")
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", envelope["nonce"]):
        raise ValueError("invalid nonce")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", envelope["payloadDigest"]):
        raise ValueError("invalid payload digest")
    issued = _parse_timestamp(envelope["issuedAt"])
    expires = _parse_timestamp(envelope["expiresAt"])
    now = datetime.datetime.now(datetime.timezone.utc)
    if issued < now - datetime.timedelta(minutes=5) or issued > now + datetime.timedelta(minutes=1) or expires <= issued:
        raise ValueError("invalid issuance window")
    max_days = 3653 if envelope["domain"] in {"cloudpen.audit-anchor.v2", "cloudpen.backup-manifest.v2"} else 366 if envelope["domain"] in {"cloudpen.evidence.v2", "cloudpen.assessment.v2"} else 31
    if expires > issued + datetime.timedelta(days=max_days):
        raise ValueError("invalid expiry")


def _parse_timestamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("invalid timestamp")
    return datetime.datetime.fromisoformat(value[:-1] + "+00:00")


def _response(status, code):
    return {"statusCode": status, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps({"error": code}, separators=(",", ":"))}
