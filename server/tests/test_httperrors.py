import unittest

from wachtl import httperrors


class HttpErrorsTest(unittest.TestCase):
    def test_429_explained(self):
        text = httperrors.explain("HTTP 429 von speed.cloudflare.com")
        self.assertTrue(text.startswith("HTTP 429 von speed.cloudflare.com – Zu viele Anfragen"))
        self.assertIn("Rate-Limit", text)

    def test_unknown_codes_fall_back_by_class(self):
        self.assertIn("Client-Fehler", httperrors.hint("HTTP 418 von x"))
        self.assertIn("vorübergehend", httperrors.hint("HTTP 599 von x"))

    def test_other_errors_unchanged(self):
        self.assertEqual(httperrors.explain("Zeitlimit erreicht"), "Zeitlimit erreicht")
        self.assertEqual(httperrors.explain(None), "")
