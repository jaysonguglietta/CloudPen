import importlib.util
import base64
import datetime
import json
import os
import pathlib
import sys
import types
import unittest


class FakeKms:
    def __init__(self):
        self.request = None

    def sign(self, **kwargs):
        self.request = kwargs
        return {"Signature": b"s" * 384}


class FakeSecrets:
    def get_secret_value(self, **_kwargs):
        return {"SecretString": "t" * 64}


fake_kms = FakeKms()
fake_boto3 = types.SimpleNamespace(client=lambda name: fake_kms if name == "kms" else FakeSecrets())
sys.modules["boto3"] = fake_boto3
os.environ.update({"KMS_KEY_ID": "kms-key", "EXPECTED_KEY_ID": "kms-key", "SIGNER_TOKEN_SECRET_ARN": "secret"})
module_path = pathlib.Path(__file__).parents[1] / "src" / "handler.py"
spec = importlib.util.spec_from_file_location("cloudpen_signer", module_path)
handler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handler)


class SignerTests(unittest.TestCase):
    def event(self, **body):
        now = datetime.datetime.now(datetime.timezone.utc)
        envelope = {
            "schema": "cloudpen.signed-artifact.v2", "protocolVersion": 2, "domain": "cloudpen.plan.v2",
            "algorithm": "PS256", "keyId": "kms-key", "workspaceId": "northstar-labs",
            "audience": "cloudpen-runner.v1", "issuedAt": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "expiresAt": (now + datetime.timedelta(minutes=15)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "nonce": "12345678-1234-4123-8123-123456789abc", "payloadDigest": "a" * 43,
        }
        message = base64.urlsafe_b64encode(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")
        payload = {"algorithm": "PS256", "keyId": "kms-key", "message": message, **body}
        return {
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"authorization": f"Bearer {'t' * 64}", "x-cloudpen-signer-protocol": "cloudpen.signed-artifact.v2"},
            "body": json.dumps(payload),
            "isBase64Encoded": False,
        }

    def test_signs_only_ps256_message_with_expected_key(self):
        response = handler.lambda_handler(self.event(), None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(fake_kms.request["SigningAlgorithm"], "RSASSA_PSS_SHA_256")
        self.assertEqual(fake_kms.request["MessageType"], "RAW")
        self.assertNotIn("error", response["body"])

    def test_rejects_bad_auth_before_signing(self):
        event = self.event()
        event["headers"]["authorization"] = "Bearer attacker"
        self.assertEqual(handler.lambda_handler(event, None)["statusCode"], 401)

    def test_rejects_unknown_fields_and_scope_changes(self):
        self.assertEqual(handler.lambda_handler(self.event(extra=True), None)["statusCode"], 400)
        self.assertEqual(handler.lambda_handler(self.event(algorithm="HS256"), None)["statusCode"], 400)
        self.assertEqual(handler.lambda_handler(self.event(keyId="other-key"), None)["statusCode"], 400)

    def test_rejects_protocol_downgrade(self):
        event = self.event()
        event["headers"]["x-cloudpen-signer-protocol"] = "cloudpen.signed-artifact.v1"
        self.assertEqual(handler.lambda_handler(event, None)["statusCode"], 400)

    def test_rejects_noncanonical_or_unapproved_envelopes(self):
        event = self.event()
        raw = json.loads(event["body"])
        raw["message"] = base64.urlsafe_b64encode(b'{"not":"an envelope"}').decode().rstrip("=")
        event["body"] = json.dumps(raw)
        self.assertEqual(handler.lambda_handler(event, None)["statusCode"], 400)


if __name__ == "__main__":
    unittest.main()
