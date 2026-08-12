import base64
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from datetime import datetime, timezone
from types import ModuleType
from unittest.mock import MagicMock


class FakeClient:
    def __getattr__(self, name):
        return MagicMock(name=name)


fake_boto3 = ModuleType("boto3")
fake_boto3.client = lambda _name: FakeClient()
sys.modules.setdefault("boto3", fake_boto3)
os.environ.update({
    "COLLECTOR_TOKEN_SECRET_ARN": "secret",
    "EVENT_BUCKET": "archive",
    "ALARM_TOPIC_ARN": "arn:aws:sns:us-east-1:111122223333:alerts",
})
spec = importlib.util.spec_from_file_location("collector_handler", os.path.join(os.path.dirname(__file__), "../src/handler.py"))
handler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handler)


def sample_event(**changes):
    value = {
        "schema": "cloudpen.security-event.v1",
        "eventId": "0f75a568-60c8-4a33-8657-c5539716fa65",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "requestId": "89d480cd-5b23-48b6-aec5-f8bdac71e8af",
        "category": "request_completed",
        "method": "GET",
        "route": "/api/control-plane",
        "status": 200,
        "outcome": "allowed",
        "actorId": "a1b2c3d4",
        "role": "admin",
        "capability": "read",
        "durationMs": 12,
        "localMode": False,
    }
    value.update(changes)
    return value


def request(value, token="t" * 64, digest=None):
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    body_digest = digest or base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
    return {
        "requestContext": {"http": {"method": "POST", "path": "/v1/events"}},
        "headers": {
            "content-type": "application/json",
            "authorization": f"Bearer {token}",
            "x-cloudpen-event-digest": body_digest,
        },
        "body": body.decode(),
        "isBase64Encoded": False,
    }


class CollectorTests(unittest.TestCase):
    def setUp(self):
        handler._token_cache.update(value=None, expires=0)
        handler._secrets.get_secret_value = MagicMock(return_value={"SecretString": "t" * 64})
        handler._s3.put_object = MagicMock(return_value={})
        handler._s3.head_object = MagicMock(return_value={})
        handler._sns.publish = MagicMock(return_value={})

    def test_accepts_and_archives_valid_event(self):
        response = handler.lambda_handler(request(sample_event()), None)
        self.assertEqual(response["statusCode"], 202)
        handler._s3.put_object.assert_called_once()

    def test_rejects_bad_token_without_archiving(self):
        response = handler.lambda_handler(request(sample_event(), token="x" * 64), None)
        self.assertEqual(response["statusCode"], 401)
        handler._s3.put_object.assert_not_called()

    def test_rejects_digest_mismatch(self):
        response = handler.lambda_handler(request(sample_event(), digest="invalid"), None)
        self.assertEqual(response["statusCode"], 400)
        handler._s3.put_object.assert_not_called()

    def test_rejects_extra_fields(self):
        response = handler.lambda_handler(request(sample_event(secret="do-not-store")), None)
        self.assertEqual(response["statusCode"], 400)

    def test_rejects_log_injection_control_characters(self):
        response = handler.lambda_handler(request(sample_event(route="/safe\nforged")), None)
        self.assertEqual(response["statusCode"], 400)
        handler._s3.put_object.assert_not_called()

    def test_alerts_on_defined_security_category(self):
        response = handler.lambda_handler(request(sample_event(category="authorization_denied", status=403, outcome="denied")), None)
        self.assertEqual(response["statusCode"], 202)
        handler._sns.publish.assert_called_once()
        self.assertNotIn("actorId", handler._sns.publish.call_args.kwargs["Message"])

    def test_does_not_alert_on_normal_request(self):
        handler.lambda_handler(request(sample_event()), None)
        handler._sns.publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
