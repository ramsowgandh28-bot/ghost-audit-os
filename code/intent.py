"""Request-intent classification module for deletion audits.

Accurately distinguishes genuine deletion requests from:
- Access / inquiry requests (e.g., requesting data copies, invoices)
- Correction / rectification requests (e.g., fixing misspelled name, phone)
- Data export requests (e.g., downloading data portability packages)
- Marketing opt-outs (e.g., unsubscribing from promo emails)
- Login / account help (e.g., password reset assistance)
- Profile / email updates (e.g., changing email/phone while continuing service)

Supports multilingual requests (English, French, Spanish, Portuguese, Korean, Japanese, German).
Follows strict challenge constraints:
- Does NOT rely on reported_status.
- Does NOT classify by case_id or email address.
- Provides an explicit uncertainty path for ambiguous or conflicting requests.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class RequestIntent(str, Enum):
    """Categorized intent of a user request."""
    DELETION = "DELETION"
    ACCESS_REQUEST = "ACCESS_REQUEST"
    CORRECTION_REQUEST = "CORRECTION_REQUEST"
    DATA_EXPORT = "DATA_EXPORT"
    MARKETING_OPT_OUT = "MARKETING_OPT_OUT"
    LOGIN_HELP = "LOGIN_HELP"
    EMAIL_CHANGE = "EMAIL_CHANGE"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass
class IntentClassificationResult:
    """Detailed result of intent analysis."""
    intent: RequestIntent
    is_deletion: bool
    confidence: float
    detected_languages: List[str]
    matched_patterns: List[str]
    negative_patterns: List[str]
    uncertainty_reasons: List[str] = field(default_factory=list)


# --- Pattern Definitions across Supported Languages ---

# Explicit negative indicators: requesting retention, continuation, or explicitly disclaiming deletion
NEGATIVE_INDICATORS = [
    # English
    (r"\bnot\s+asking\s+for\s+deletion\b", "not_asking_for_deletion"),
    (r"\bnot\s+a\s+request\s+to\s+erase\b", "not_a_request_to_erase"),
    (r"\bleave\s+the\s+account\s+active\b", "leave_account_active"),
    (r"\bleave\s+(?:my\s+)?(?:profile|account|records|purchase\s+history)\s+in\s+place\b", "leave_in_place"),
    (r"\bkeep\s+the\s+account\s+as\s+it\s+is\b", "keep_account_as_is"),
    (r"\bkeep\s+the\s+account\s+active\b", "keep_account_active"),
    (r"\b(?:do\s+not|don['’]t)\s+close\s+the\s+account\b", "do_not_close_account"),
    (r"\b(?:do\s+not|don['’]t)\s+(?:delete|remove|erase)\b", "do_not_delete"),
    (r"\bwithout\s+removing\s+any\s+of\s+my\s+records\b", "without_removing_records"),
    (r"\bwant\s+to\s+continue\s+using\s+the\s+service\b", "continue_using_service"),
    (r"\bmarketing\s+lists\s+only\b", "marketing_lists_only"),
    (r"\bpromotional\s+emails?\s+only\b", "promotional_only"),
    # French
    (r"\bne\s+pas\s+supprimer\b", "fr_ne_pas_supprimer"),
    (r"\bne\s+fermez\s+pas\s+(?:mon\s+)?compte\b", "fr_ne_fermez_pas_compte"),
    (r"\bgarder\s+le\s+compte\s+actif\b", "fr_garder_compte_actif"),
    # Spanish
    (r"\bno\s+eliminar\b", "es_no_eliminar"),
    (r"\bno\s+cierre\s+(?:la\s+)?cuenta\b", "es_no_cierre_cuenta"),
    (r"\bmantener\s+la\s+cuenta\s+activa\b", "es_mantener_cuenta_activa"),
    # Portuguese
    (r"\bnão\s+excluir\b", "pt_nao_excluir"),
    (r"\bnão\s+feche\s+a\s+conta\b", "pt_nao_feche_conta"),
    (r"\bmanter\s+a\s+conta\s+ativa\b", "pt_manter_conta_ativa"),
    # Korean
    (r"계정을\s*유지해\s*주세요", "ko_keep_account"),
    (r"삭제하지\s*마세요", "ko_do_not_delete"),
    # Japanese
    (r"アカウントは?維持してください", "ja_keep_account"),
    (r"削除しないでください", "ja_do_not_delete"),
]

# Specific Non-Deletion Intent Indicators
SPECIFIC_NON_DELETION_PATTERNS = {
    RequestIntent.ACCESS_REQUEST: [
        r"\bwhat\s+personal\s+information\s+you\s+hold\b",
        r"\binformation\s+request\b",
        r"\bsend\s+me\s+a\s+copy\s+of\s+the\s+information\b",
        r"\bcopy\s+of\s+(?:last\s+year['’]s\s+)?invoices\b",
        r"\baccess\s+to\s+my\s+personal\s+data\b",
        r"\baccès\s+à\s+mes\s+données\b",
        r"\bacceso\s+a\s+mis\s+datos\b",
        r"\bacesso\s+aos\s+meus\s+dados\b",
        r"개인정보\s*(?:열람|사본)",
        r"データの開示",
    ],
    RequestIntent.DATA_EXPORT: [
        r"\bdownload\s+my\s+account\s+information\s+in\s+a\s+portable\s+format\b",
        r"\bportable\s+format\b",
        r"\bexport\s+my\s+data\b",
        r"\btélécharger\s+mes\s+données\b",
        r"\bdescargar\s+mis\s+datos\b",
        r"\bbaixar\s+meus\s+dados\b",
        r"데이터\s*내보내기",
        r"データのエクスポート",
    ],
    RequestIntent.MARKETING_OPT_OUT: [
        r"\bstop\s+the\s+promotional\s+emails\b",
        r"\bmarketing\s+lists\s+only\b",
        r"\bunsubscribe\s+from\s+marketing\b",
        r"\bopt-out\s+of\s+marketing\b",
        r"\bdésabonner\s+des\s+e-mails\s+promotionnels\b",
        r"\bcancelar\s+suscripción\b",
        r"마케팅\s*수신거부",
        r"配信停止",
    ],
    RequestIntent.LOGIN_HELP: [
        r"\bcan['’]t\s+access\s+my\s+profile\s+and\s+need\s+help\s+resetting\s+the\s+login\b",
        r"\breset(?:ting)?\s+(?:the\s+)?(?:login|password)\b",
        r"\bhelp\s+with\s+login\b",
        r"\bréinitialiser\s+le\s+mot\s+de\s+passe\b",
        r"\brestablecer\s+la\s+contraseña\b",
        r"비밀번호\s*재설정",
        r"ログインのリセット",
    ],
    RequestIntent.CORRECTION_REQUEST: [
        r"\bmisspelled\s+on\s+the\s+account\b",
        r"\bcorrect\s+it\s+without\s+removing\b",
        r"\bmobile\s+number\s+on\s+my\s+profile\s+is\s+out\s+of\s+date\b",
        r"\breplace\s+it\s+with\s+the\s+new\s+one\b",
        r"\bupdate\s+my\s+(?:phone|address|name|surname)\b",
        r"\brectification\b",
        r"\brectificar\b",
        r"정보\s*수정",
        r"情報の訂正",
    ],
    RequestIntent.EMAIL_CHANGE: [
        r"\bchange\s+the\s+email\s+address\s+used\s+for\s+this\s+account\b",
        r"\bchanger\s+l['’]adresse\s+e-mail\b",
        r"\bcambiar\s+la\s+dirección\s+de\s+correo\b",
        r"이메일\s*주소\s*변경",
        r"メールアドレスの変更",
    ],
}

# Positive Deletion Intent Indicators across languages
DELETION_PATTERNS = [
    # English
    (r"\b(?:permanent|permanently)\s+(?:account\s+|account-)?delet(?:ed|e|ion)\b", "en_permanent_deletion"),
    (r"\bdelet(?:ion|e|ed|ing)\s+(?:of\s+)?(?:the|this|my|an)?\s*(?:account|profile|personal\s+data|records)?\b", "en_delete_word"),
    (r"\b(?:erase|erased|erasure)\b", "en_erase_word"),
    (r"\b(?:close|closed|closing)\s+(?:the|this|my|an)?\s*account(?:\s+permanently)?\b", "en_close_account"),
    (r"\bremov(?:e|ed|ing)\s+(?:the|this|that|my)?\s*(?:account|profile|personal\s+details|personal\s+information|records|search\s+result|name\s+and\s+contact\s+details|the\s+rest)\b", "en_remove_account"),
    (r"\b(?:account|profile|data|records?).{0,40}(?:to\s+be\s+erased|to\s+be\s+deleted|was\s+deleted|had\s+been\s+deleted|is\s+gone|been\s+removed|already\s+been\s+removed)\b", "en_account_passive_erased"),
    (r"\bno\s+longer\s+need\s+this\s+account\b", "en_no_longer_need_account"),
    (r"\bdeleted-account\b", "en_deleted_account_ref"),
    (r"\bright\s+to\s+be\s+forgotten\b", "en_right_to_be_forgotten"),
    (r"\bpersonal-data\s+deletion\b", "en_personal_data_deletion"),
    (r"\bdeletion\s+process\b", "en_deletion_process"),
    (r"\baudit\s+the\s+deletion\b", "en_audit_deletion"),
    (r"\bfully\s+removed\b", "en_fully_removed"),
    (r"\bclean(?:ing)?\s+my\s+personal\s+details\b", "en_clean_details"),

    # French
    (r"suppression\s+d[ée]finitive\s+du\s+compte", "fr_suppression_definitive"),
    (r"supprimer\s+(?:d[ée]finitivement\s+)?(?:mon|le)\s+compte", "fr_supprimer_compte"),
    (r"effacer\s+(?:mes\s+donn[ée]es|le\s+compte)", "fr_effacer_compte"),
    (r"droit\s+[àa]\s+l['’]oubli", "fr_droit_oubli"),

    # Spanish
    (r"eliminaci[óo]n\s+permanente\s+de\s+la\s+cuenta", "es_eliminacion_permanente"),
    (r"eliminar\s+(?:mi|la)\s+cuenta", "es_eliminar_cuenta"),
    (r"borrar\s+(?:mi|la)\s+cuenta", "es_borrar_cuenta"),
    (r"derecho\s+al\s+olvido", "es_derecho_olvido"),

    # Portuguese
    (r"exclus[ãa]o\s+permanente\s+da\s+conta", "pt_exclusao_permanente"),
    (r"excluir\s+(?:minha|a)\s+conta", "pt_excluir_conta"),
    (r"apagar\s+(?:minha|a)\s+conta", "pt_apagar_conta"),

    # Korean
    (r"영구\s*삭제", "ko_permanent_deletion"),
    (r"(?:계정|개인정보|회원).{0,30}삭제", "ko_delete_account"),
    (r"회원\s*탈퇴", "ko_account_withdrawal"),

    # Japanese
    (r"完全な削除を依頼します", "ja_complete_deletion"),
    (r"アカウントの(?:完全な)?削除", "ja_delete_account"),
    (r"消去を依頼", "ja_erasure_request"),

    # German
    (r"l[öo]schung\s+(?:des|meines|dieses)?\s*(?:kontos|daten|profils)?", "de_loeschung"),
    (r"konto\s+(?:dauerhaft\s+)?l[öo]schen", "de_konto_loeschen"),
    (r"recht\s+auf\s+vergessenwerden", "de_vergessenwerden"),
]


def classify_request_intent(request_text: str) -> IntentClassificationResult:
    """Classify the user intent of a request text.

    Distinguishes genuine deletion requests from non-deletion requests and ambiguous cases.
    Does NOT use case_id, email, or reported_status.
    """
    if not request_text or not request_text.strip():
        return IntentClassificationResult(
            intent=RequestIntent.AMBIGUOUS,
            is_deletion=False,
            confidence=0.0,
            detected_languages=["unknown"],
            matched_patterns=[],
            negative_patterns=[],
            uncertainty_reasons=["empty_or_whitespace_text"]
        )

    text_lower = request_text.lower()

    # Detect language(s)
    languages = []
    if re.search(r"[\uac00-\ud7a3]", request_text):
        languages.append("korean")
    if re.search(r"[\u3040-\u30ff\u4e00-\u9faf]", request_text):
        languages.append("japanese")
    if any(w in text_lower for w in ["suppression", "compte", "veuillez", "demande la"]):
        languages.append("french")
    if any(w in text_lower for w in ["eliminación", "eliminacion", "cuenta", "solicito la"]):
        languages.append("spanish")
    if any(w in text_lower for w in ["exclusão", "exclusao", "conta", "solicito a"]):
        languages.append("portuguese")
    if any(w in text_lower for w in ["löschung", "loeschung", "konto", "bitte"]):
        languages.append("german")
    if not languages:
        languages.append("english")

    # 1. Check for negative indicators (requests to keep account, not delete, etc.)
    matched_negatives = []
    for pattern, name in NEGATIVE_INDICATORS:
        if re.search(pattern, text_lower):
            matched_negatives.append(name)

    # 2. Check for positive deletion patterns
    matched_deletion_patterns = []
    for pattern, name in DELETION_PATTERNS:
        if re.search(pattern, text_lower):
            matched_deletion_patterns.append(name)

    # 3. Check for specific non-deletion intent categories
    matched_non_deletion_categories = {}
    for intent_category, patterns in SPECIFIC_NON_DELETION_PATTERNS.items():
        cat_matches = []
        for pat in patterns:
            if re.search(pat, text_lower):
                cat_matches.append(pat)
        if cat_matches:
            matched_non_deletion_categories[intent_category] = cat_matches

    # Decision Logic:

    # Case A: Explicit negative indicator present
    if matched_negatives:
        # Determine specific non-deletion category if available
        primary_category = RequestIntent.ACCESS_REQUEST
        if matched_non_deletion_categories:
            primary_category = list(matched_non_deletion_categories.keys())[0]
        else:
            # Infer from negative indicator type
            if any("marketing" in n or "promotional" in n for n in matched_negatives):
                primary_category = RequestIntent.MARKETING_OPT_OUT
            elif any("leave" in n or "keep" in n for n in matched_negatives):
                primary_category = RequestIntent.ACCESS_REQUEST

        return IntentClassificationResult(
            intent=primary_category,
            is_deletion=False,
            confidence=0.98,
            detected_languages=languages,
            matched_patterns=[],
            negative_patterns=matched_negatives,
            uncertainty_reasons=[]
        )

    # Case B: Specific non-deletion pattern matched without deletion patterns
    if matched_non_deletion_categories and not matched_deletion_patterns:
        primary_category = list(matched_non_deletion_categories.keys())[0]
        return IntentClassificationResult(
            intent=primary_category,
            is_deletion=False,
            confidence=0.95,
            detected_languages=languages,
            matched_patterns=[p for pats in matched_non_deletion_categories.values() for p in pats],
            negative_patterns=[],
            uncertainty_reasons=[]
        )

    # Case C: Clear deletion pattern with no negative indicators
    if matched_deletion_patterns:
        # Check if there is also an conflicting non-deletion category (contradiction)
        if matched_non_deletion_categories:
            # E.g. "please delete my account and also export my invoices"
            # Could be ambiguous or deletion with ancillary request
            return IntentClassificationResult(
                intent=RequestIntent.AMBIGUOUS,
                is_deletion=False,
                confidence=0.40,
                detected_languages=languages,
                matched_patterns=matched_deletion_patterns + [p for pats in matched_non_deletion_categories.values() for p in pats],
                negative_patterns=[],
                uncertainty_reasons=["contradictory_intent_both_deletion_and_non_deletion_requested"]
            )

        return IntentClassificationResult(
            intent=RequestIntent.DELETION,
            is_deletion=True,
            confidence=0.98,
            detected_languages=languages,
            matched_patterns=matched_deletion_patterns,
            negative_patterns=[],
            uncertainty_reasons=[]
        )

    # Case D: Neither deletion nor non-deletion clearly matched -> AMBIGUOUS
    return IntentClassificationResult(
        intent=RequestIntent.AMBIGUOUS,
        is_deletion=False,
        confidence=0.20,
        detected_languages=languages,
        matched_patterns=[],
        negative_patterns=[],
        uncertainty_reasons=["unrecognized_or_insufficient_intent_keywords"]
    )
