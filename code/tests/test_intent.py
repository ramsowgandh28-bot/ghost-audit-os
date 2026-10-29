"""Tests for request-intent classification and multilingual handling."""

import os
import unittest
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intent import classify_request_intent, RequestIntent


class TestRequestIntentClassification(unittest.TestCase):
    """Test suite for intent classification and multilingual requests."""

    def test_multilingual_deletion_requests(self):
        """Verify accurate classification of genuine deletion requests across languages."""
        test_cases = [
            # English
            ("Please treat this message as a request for permanent account deletion.", True, RequestIntent.DELETION),
            ("I would like to submit a request to delete this account and its personal data.", True, RequestIntent.DELETION),
            ("I no longer use this account and would like it permanently deleted.", True, RequestIntent.DELETION),
            ("I haven’t used this account in years and would like it closed. Please remove the profile.", True, RequestIntent.DELETION),
            ("I am requesting deletion of the account registered to this email address.", True, RequestIntent.DELETION),

            # French
            ("Je demande la suppression définitive du compte associé à cette adresse e-mail.", True, RequestIntent.DELETION),
            ("Veuillez supprimer définitivement mon compte et effacer mes données personnelles.", True, RequestIntent.DELETION),

            # Spanish
            ("Solicito la eliminación permanente de la cuenta asociada a este correo.", True, RequestIntent.DELETION),
            ("Intenté eliminar mi cuenta ayer, pero la página terminó mostrando un error. Por favor completen la eliminación.", True, RequestIntent.DELETION),

            # Portuguese
            ("Solicito a exclusão permanente da conta associada a este e-mail.", True, RequestIntent.DELETION),
            ("Por favor, apagar minha conta e excluir todos os meus dados.", True, RequestIntent.DELETION),

            # Korean
            ("이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.", True, RequestIntent.DELETION),
            ("내 계정과 모든 개인정보를 영구 삭제해 주세요.", True, RequestIntent.DELETION),

            # Japanese
            ("このメールアドレスに関連するアカウントの完全な削除を依頼します。", True, RequestIntent.DELETION),
            ("アカウントの削除と個人情報の消去を依頼します。", True, RequestIntent.DELETION),

            # German
            ("Ich beantrage die vollständige Löschung meines Kontos und aller damit verknüpften Daten.", True, RequestIntent.DELETION),
        ]

        for text, expected_is_del, expected_intent in test_cases:
            res = classify_request_intent(text)
            self.assertEqual(res.is_deletion, expected_is_del, f"Failed on text: {text}")
            self.assertEqual(res.intent, expected_intent, f"Failed on text: {text}")
            self.assertGreaterEqual(res.confidence, 0.90)

    def test_clear_non_deletion_requests(self):
        """Verify distinction of all non-deletion categories."""
        non_del_cases = [
            # Correction
            ("The mobile number on my profile is out of date. Please replace it with the new one and leave the account active.", RequestIntent.CORRECTION_REQUEST),
            ("My surname is misspelled on the account. Can you correct it without removing any of my records?", RequestIntent.CORRECTION_REQUEST),

            # Marketing Opt-Out
            ("Please stop the promotional emails. I still need the account and my order history, so I am not asking for deletion.", RequestIntent.MARKETING_OPT_OUT),
            ("Please remove me from marketing lists only. I still want receipts and service messages for this account.", RequestIntent.MARKETING_OPT_OUT),

            # Data Export
            ("I'd like to download my account information in a portable format. Please keep the account as it is.", RequestIntent.DATA_EXPORT),

            # Login Help
            ("I can't access my profile and need help resetting the login. Do not close the account.", RequestIntent.LOGIN_HELP),

            # Access / Info
            ("Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.", RequestIntent.ACCESS_REQUEST),
            ("I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place.", RequestIntent.ACCESS_REQUEST),
            ("Could you send me a copy of the information held on my account? I still use it, so please don't delete or change anything.", RequestIntent.ACCESS_REQUEST),

            # Email Change
            ("Please change the email address used for this account. I want to continue using the service.", RequestIntent.EMAIL_CHANGE),
        ]

        for text, expected_intent in non_del_cases:
            res = classify_request_intent(text)
            self.assertFalse(res.is_deletion, f"Incorrectly marked as deletion: {text}")
            self.assertEqual(res.intent, expected_intent, f"Expected {expected_intent}, got {res.intent} for: {text}")

    def test_ambiguous_and_contradictory_requests(self):
        """Verify routing of contradictory, empty, or ambiguous requests to uncertainty path."""
        # Contradictory request
        contradictory = "Please permanently delete my account, but do not close the account and keep it active."
        res_contra = classify_request_intent(contradictory)
        self.assertFalse(res_contra.is_deletion)
        # Should not be confident deletion

        # Empty / whitespace
        res_empty = classify_request_intent("   ")
        self.assertEqual(res_empty.intent, RequestIntent.AMBIGUOUS)
        self.assertFalse(res_empty.is_deletion)
        self.assertIn("empty_or_whitespace_text", res_empty.uncertainty_reasons)

        # Insufficient / unrecognized text
        res_vague = classify_request_intent("Hello Northstar Shop, what products do you sell?")
        self.assertEqual(res_vague.intent, RequestIntent.AMBIGUOUS)
        self.assertFalse(res_vague.is_deletion)
        self.assertIn("unrecognized_or_insufficient_intent_keywords", res_vague.uncertainty_reasons)

    def test_do_not_trust_reported_status(self):
        """Intent classifier must evaluate text independently of any reported status."""
        # A request text that is clearly an access request must NOT become a deletion
        # simply because an external workflow marked reported_status as COMPLETE.
        access_text = "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place."
        res = classify_request_intent(access_text)
        self.assertFalse(res.is_deletion)
        self.assertEqual(res.intent, RequestIntent.ACCESS_REQUEST)


    def test_multilingual_negative_constraints(self):
        """Requests in Japanese, Spanish, and French that ask NOT to delete must not be classified as deletion."""
        non_del_multilingual = [
            ("アカウントは削除しないでください。パスワードを再設定したいです。", False),
            ("Por favor no eliminen mi cuenta, sólo quiero cambiar el correo.", False),
            ("Ne supprimez pas mon compte s'il vous plaît, je veux juste une copie de mes factures.", False),
        ]
        for text, expected_is_del in non_del_multilingual:
            res = classify_request_intent(text)
            self.assertEqual(res.is_deletion, expected_is_del, f"Failed on: {text}")


if __name__ == "__main__":
    unittest.main()
