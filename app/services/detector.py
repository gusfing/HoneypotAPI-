"""
Scam Detector - Classifies incoming messages by scam type using keyword analysis.
Supports: bank_fraud, upi_fraud, phishing, investment_scam, lottery_scam, generic_scam.
"""
import logging

logger = logging.getLogger(__name__)

# Scam type keyword patterns (weighted)
SCAM_PATTERNS = {
    "bank_fraud": {
        "keywords": [
            "account", "bank", "blocked", "compromised", "otp", "debit", "credit",
            "transaction", "unauthorized", "suspend", "freeze", "kyc", "verify",
            "sbi", "hdfc", "icici", "axis", "pnb", "rbi", "reserve bank",
            "atm", "pin", "cvv", "card number", "netbanking", "password",
            "deactivat", "closed", "locked", "security alert", "fraud department",
        ],
        "weight": 1.0,
    },
    "upi_fraud": {
        "keywords": [
            "upi", "gpay", "phonepe", "paytm", "google pay", "bhim",
            "cashback", "refund", "payment", "transfer", "collect request",
            "upi id", "upi pin", "send money", "receive money", "qr code",
            "vpa", "wallet", "recharge",
        ],
        "weight": 1.0,
    },
    "phishing": {
        "keywords": [
            "click", "link", "url", "offer", "deal", "discount", "coupon",
            "amazon", "flipkart", "prize", "claim", "congratulations", "selected",
            "gift", "voucher", "free", "limited time", "expire", "act now",
            "http://", "https://", ".com", "login", "update your",
            "verify your", "confirm your", "subscribe",
        ],
        "weight": 1.0,
    },
    "investment_scam": {
        "keywords": [
            "invest", "return", "profit", "guaranteed", "double", "triple",
            "stock", "trading", "crypto", "bitcoin", "mutual fund", "scheme",
            "high return", "risk free", "monthly income", "passive income",
            "forex", "binary option",
        ],
        "weight": 0.9,
    },
    "lottery_scam": {
        "keywords": [
            "lottery", "won", "winner", "prize", "lucky", "draw", "jackpot",
            "million", "crore", "lakh", "claim your", "winner notification",
            "sweepstakes", "raffle",
        ],
        "weight": 0.9,
    },
}

# Universal scam indicators
URGENCY_KEYWORDS = [
    "urgent", "immediately", "right now", "asap", "hurry", "quickly",
    "within hours", "last chance", "don't delay", "act fast", "time sensitive",
    "expiring", "deadline", "final warning", "last warning",
]


def detect_scam(text: str, conversation_history: list = None) -> dict:
    """
    Analyze text for scam indicators.
    Returns: {"is_scam": bool, "scam_type": str, "confidence": float, "indicators": list}
    """
    text_lower = text.lower()
    
    # Also analyze full conversation if available
    full_text = text_lower
    if conversation_history:
        for msg in conversation_history:
            if msg.get("sender") == "scammer":
                full_text += " " + msg.get("text", "").lower()
    
    scores = {}
    all_indicators = []
    
    # Score each scam type
    for scam_type, config in SCAM_PATTERNS.items():
        score = 0
        for keyword in config["keywords"]:
            if keyword.lower() in full_text:
                score += config["weight"]
                all_indicators.append(f"{scam_type}: '{keyword}'")
        scores[scam_type] = score
    
    # Check urgency
    urgency_score = 0
    for keyword in URGENCY_KEYWORDS:
        if keyword in full_text:
            urgency_score += 1
            all_indicators.append(f"urgency: '{keyword}'")
    
    # Determine primary scam type
    if scores:
        best_type = max(scores, key=scores.get)
        best_score = scores[best_type]
    else:
        best_type = "generic_scam"
        best_score = 0
    
    # Always flag as scam (honeypot assumption)
    # But adjust confidence based on evidence
    total_evidence = best_score + urgency_score
    confidence = min(0.99, 0.6 + (total_evidence * 0.05))
    
    return {
        "is_scam": True,  # Always true for honeypot
        "scam_type": best_type if best_score > 0 else "generic_scam",
        "confidence": round(confidence, 2),
        "indicators": all_indicators[:10],  # Top 10
        "urgency_level": min(urgency_score, 5),
    }
