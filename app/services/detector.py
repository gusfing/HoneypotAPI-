"""
Scam Detector - Classifies incoming messages by scam type using heuristic analysis.
Supports: bank_fraud, upi_fraud, phishing, investment_scam, lottery_scam, generic_scam.
"""
import logging
import re
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Pre-compile scam pattern dictionaries for O(1) matching during iteration
SCAM_PATTERNS: Dict[str, Dict[str, Any]] = {
    "bank_fraud": {
        "patterns": [
            re.compile(rf"\b{re.escape(k)}\b", re.IGNORECASE) for k in [
                "account", "bank", "blocked", "compromised", "otp", "debit", "credit",
                "transaction", "unauthorized", "suspend", "freeze", "kyc", "verify",
                "sbi", "hdfc", "icici", "axis", "pnb", "rbi", "reserve bank",
                "atm", "pin", "cvv", "card number", "netbanking", "password",
                "deactivat", "closed", "locked", "security alert", "fraud department",
            ]
        ],
        "weight": 1.0,
    },
    "upi_fraud": {
        "patterns": [
            re.compile(rf"\b{re.escape(k)}\b", re.IGNORECASE) for k in [
                "upi", "gpay", "phonepe", "paytm", "google pay", "bhim",
                "cashback", "refund", "payment", "transfer", "collect request",
                "upi id", "upi pin", "send money", "receive money", "qr code",
                "vpa", "wallet", "recharge",
            ]
        ],
        "weight": 1.0,
    },
    "phishing": {
        "patterns": [
            re.compile(rf"\b{re.escape(k)}\b", re.IGNORECASE) for k in [
                "click", "link", "url", "offer", "deal", "discount", "coupon",
                "amazon", "flipkart", "prize", "claim", "congratulations", "selected",
                "gift", "voucher", "free", "limited time", "expire", "act now",
                "login", "update your", "verify your", "confirm your", "subscribe",
            ]
        ] + [
            # Direct HTTP protocols don't need word boundaries
            re.compile(r"https?://", re.IGNORECASE),
            re.compile(r"\.com\b", re.IGNORECASE),
        ],
        "weight": 1.0,
    },
    "investment_scam": {
        "patterns": [
            re.compile(rf"\b{re.escape(k)}\b", re.IGNORECASE) for k in [
                "invest", "return", "profit", "guaranteed", "double", "triple",
                "stock", "trading", "crypto", "bitcoin", "mutual fund", "scheme",
                "high return", "risk free", "monthly income", "passive income",
                "forex", "binary option",
            ]
        ],
        "weight": 0.9,
    },
    "lottery_scam": {
        "patterns": [
            re.compile(rf"\b{re.escape(k)}\b", re.IGNORECASE) for k in [
                "lottery", "won", "winner", "prize", "lucky", "draw", "jackpot",
                "million", "crore", "lakh", "claim your", "winner notification",
                "sweepstakes", "raffle",
            ]
        ],
        "weight": 0.9,
    },
    "generic_scam": {
        "patterns": [
            re.compile(rf"\b{re.escape(k)}\b", re.IGNORECASE) for k in [
                "police", "customs", "delivery", "fbi", "interpol", "arrest", 
                "warrant", "fine", "penalty", "package", "parcel", "held",
                "tax", "irs", "revenue", "department", "social security",
            ]
        ],
        "weight": 0.5,
    }
}

# Universal scam indicators focusing on urgency/threats
URGENCY_PATTERNS: List[re.Pattern] = [
    re.compile(rf"\b{re.escape(k)}\b", re.IGNORECASE) for k in [
        "urgent", "immediately", "right now", "asap", "hurry", "quickly",
        "within hours", "last chance", "don't delay", "act fast", "time sensitive",
        "expiring", "deadline", "final warning", "last warning",
    ]
]


def detect_scam(text: str, conversation_history: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Analyze text for scam indicators using heuristic regex boundary matching.
    
    Args:
        text (str): The current incoming message text to analyze.
        conversation_history (List[Dict[str, Any]], optional): The preceding chat context for cumulative history search. Defaults to None.
        
    Returns: 
        Dict[str, Any]: {"is_scam": bool, "scam_type": str, "confidence": float, "indicators": list, "urgency_level": int}
    """
    if not text:
        text = ""
        
    # Collate current history logs to look for trailing indicators
    full_text = text
    if conversation_history:
        for msg in conversation_history:
            if isinstance(msg, dict) and msg.get("sender") == "scammer":
                full_text += " " + str(msg.get("text", ""))
            elif hasattr(msg, "sender") and getattr(msg, "sender") == "scammer":
                full_text += " " + str(getattr(msg, "text", ""))
    
    scores: Dict[str, float] = {}
    all_indicators: List[str] = []
    
    # Score each scam type by executing the compiled regex boundaries
    for scam_type, config in SCAM_PATTERNS.items():
        score = 0.0
        patterns: List[re.Pattern] = config["patterns"]
        weight: float = config["weight"]
        
        for pattern in patterns:
            # Reconstruct the string pattern for the indicator log
            clean_str = pattern.pattern.replace(r"\b", "").replace("\\", "").lower()
            if pattern.search(full_text):
                score += weight
                all_indicators.append(f"{scam_type}: '{clean_str}'")
                
        scores[scam_type] = score
    
    # Measure conversational pressure and urgency
    urgency_score = 0
    for pattern in URGENCY_PATTERNS:
        clean_str = pattern.pattern.replace(r"\b", "").replace("\\", "").lower()
        if pattern.search(full_text):
            urgency_score += 1
            all_indicators.append(f"urgency: '{clean_str}'")
    
    # Evaluate primary scam type based on weighted heuristics
    best_type = "generic_scam"
    best_score = 0.0
    
    if scores:
        type_choice = max(scores, key=scores.get)
        if scores[type_choice] > 0:
            best_type = type_choice
            best_score = scores[type_choice]
            
    # Calculate analytical confidence ratio (1.0 = Max Threat Level)
    total_evidence = best_score + urgency_score
    confidence = min(0.99, 0.6 + (total_evidence * 0.05))
    
    return {
        "is_scam": True,  # Constant given Honeypot Assumption
        "scam_type": best_type,
        "confidence": round(confidence, 2),
        "indicators": all_indicators[:10],
        "urgency_level": min(urgency_score, 5),
    }
