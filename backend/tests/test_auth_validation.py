import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException


ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "backend"))

from app import main


class TestAuthValidation(unittest.TestCase):
    def test_validate_user_payload_uses_email_mapping(self):
        payload = {"userId": 999, "email": "user@example.com"}
        with patch("app.main._fetch_user_by_email", return_value={"id": 2, "email": "user@example.com"}):
            validated = main._validate_user_payload(payload)
        self.assertEqual(validated["userId"], 2)
        self.assertEqual(validated["email"], "user@example.com")

    def test_validate_user_payload_rejects_unknown_email(self):
        payload = {"userId": 1, "email": "missing@example.com"}
        with patch("app.main._fetch_user_by_email", return_value=None):
            with self.assertRaises(HTTPException) as ctx:
                main._validate_user_payload(payload)
        self.assertEqual(ctx.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
