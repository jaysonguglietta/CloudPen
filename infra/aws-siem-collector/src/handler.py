import base64
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

import boto3


_secrets = boto3.client("secretsmanager")
_s3 = boto3.client("s3")
_sns = boto3.client("sns")
_token_cache = {"value": None, "expires": 0.0}
_EVENT_KEYS = {
    "schema", "eventId", "timestamp", "requestId", "category", "method", "route",
    "status", "outcome", "actorId", "role", "capability", "durationMs", "localMode",
}
_OUTCOMES = {"allowed", "denied", "alert"}
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_ALERT_CATEGORIES = {
    "authorization_denied", "cross_origin_denied", "body_size_denied",
    "rate_limit_denied", "internal_failure", "identity_origin_denied",
    "audit_verification_failed", "signing_failure", "production_configuration_denied",
}
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")


def _response(status, body=None):
    payload = {} if body is None else body
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps(payload, separators=(",", ":")),
    }


def _bearer_token():
    now = time.monotonic()
    if _token_cache["value"] and _token_cache["expires"] > now:
        return _token_cache["value"]
    value = _secrets.get_secret_value(SecretId=os.environ["COLLECTOR_TOKEN_SECRET_ARN"])["SecretString"]
    if not isinstance(value, str) or len(value) < 32:
        raise RuntimeError("Collector credential is invalid")
    _token_cache.update(value=value, expires=now + 300)
    return value


def _headers(event):
    return {str(key).lower(): str(value) for key, value in (event.get("headers") or {}).items()}


def _decode_body(event):
    raw = event.get("body")
    if not isinstance(raw, str):
        raise ValueError("missing_body")
    try:
        body = base64.b64decode(raw, validate=True) if event.get("isBase64Encoded") else raw.encode("utf-8")
    except (ValueError, UnicodeError):
        raise ValueError("invalid_body")
    if not body or len(body) > 16_384:
        raise ValueError("invalid_body_size")
    return body


def _validate_event(value, now):
    if not isinstance(value, dict) or set(value) != _EVENT_KEYS:
        raise ValueError("invalid_schema_fields")
    if value.get("schema") != "cloudpen.security-event.v1":
        raise ValueError("invalid_schema")
    try:
        parsed_event_id = uuid.UUID(value["eventId"])
        if parsed_event_id.version != 4 or str(parsed_event_id) != value["eventId"].lower():
            raise ValueError("invalid_event_id")
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ValueError("invalid_event_id")
    try:
        timestamp = datetime.fromisoformat(value["timestamp"].replace("Z", "+00:00"))
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ValueError("invalid_timestamp")
    if timestamp.tzinfo is None:
        raise ValueError("invalid_timestamp")
    timestamp = timestamp.astimezone(timezone.utc)
    if timestamp > now + timedelta(minutes=5) or timestamp < now - timedelta(days=30):
        raise ValueError("timestamp_out_of_range")
    if value.get("outcome") not in _OUTCOMES or value.get("method") not in _METHODS:
        raise ValueError("invalid_event_value")
    if not isinstance(value.get("status"), int) or not 100 <= value["status"] <= 599:
        raise ValueError("invalid_status")
    if not isinstance(value.get("durationMs"), int) or not 0 <= value["durationMs"] <= 600_000:
        raise ValueError("invalid_duration")
    if not isinstance(value.get("localMode"), bool):
        raise ValueError("invalid_local_mode")
    if not isinstance(value.get("category"), str) or not _SAFE_TEXT.fullmatch(value["category"]):
        raise ValueError("invalid_category")
    route = value.get("route")
    if not isinstance(route, str) or not 1 <= len(route) <= 512 or any(ord(character) < 32 for character in route):
        raise ValueError("invalid_route")
    for key in ("requestId", "actorId", "role", "capability"):
        item = value.get(key)
        if item is not None and (not isinstance(item, str) or not _SAFE_TEXT.fullmatch(item)):
            raise ValueError(f"invalid_{key}")
    return timestamp


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _persist(value, body_digest, timestamp):
    key = f"events/{timestamp:%Y/%m/%d}/{value['eventId']}.json"
    canonical = _canonical(value)
    canonical_digest = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode("ascii")
    try:
        _s3.put_object(
            Bucket=os.environ["EVENT_BUCKET"],
            Key=key,
            Body=canonical,
            ContentType="application/json",
            Metadata={"event-id": value["eventId"], "body-digest": body_digest, "canonical-digest": canonical_digest},
            IfNoneMatch="*",
        )
        return "accepted"
    except Exception as error:
        response = getattr(error, "response", {})
        if response.get("Error", {}).get("Code") not in {"PreconditionFailed", "412", "ConditionalRequestConflict", "409"}:
            raise
        existing = _s3.head_object(Bucket=os.environ["EVENT_BUCKET"], Key=key)
        if existing.get("Metadata", {}).get("canonical-digest") != canonical_digest:
            raise ValueError("event_id_conflict")
        return "duplicate"


def _alert(value):
    if value["category"] not in _ALERT_CATEGORIES and not value["localMode"]:
        return
    message = {
        "schema": "cloudpen.security-alert.v1",
        "eventId": value["eventId"],
        "timestamp": value["timestamp"],
        "category": value["category"],
        "outcome": value["outcome"],
        "localMode": value["localMode"],
    }
    _sns.publish(
        TopicArn=os.environ["ALARM_TOPIC_ARN"],
        Subject=f"CloudPen security alert: {value['category']}"[:100],
        Message=json.dumps(message, sort_keys=True, separators=(",", ":")),
    )


def lambda_handler(event, _context):
    request_context = event.get("requestContext", {}).get("http", {})
    if request_context.get("method") != "POST" or request_context.get("path") != "/v1/events":
        return _response(404, {"error": "not_found"})
    headers = _headers(event)
    if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return _response(415, {"error": "unsupported_media_type"})
    authorization = headers.get("authorization", "")
    expected = f"Bearer {_bearer_token()}"
    if not hmac.compare_digest(authorization, expected):
        return _response(401, {"error": "unauthorized"})
    try:
        body = _decode_body(event)
        supplied_digest = headers.get("x-cloudpen-event-digest", "")
        computed_digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode("ascii")
        if not supplied_digest or not hmac.compare_digest(supplied_digest, computed_digest):
            raise ValueError("digest_mismatch")
        value = json.loads(body)
        timestamp = _validate_event(value, datetime.now(timezone.utc))
        disposition = _persist(value, supplied_digest, timestamp)
        if disposition == "accepted":
            _alert(value)
        return _response(202 if disposition == "accepted" else 200, {"status": disposition})
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return _response(409 if str(error) == "event_id_conflict" else 400, {"error": str(error)[:64]})
