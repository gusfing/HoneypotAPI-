"""
Intelligence Extractor - Extracts phone numbers, bank accounts, UPI IDs, URLs, and emails
from scammer messages using robust regex patterns.
This is the HIGHEST VALUE component (40 pts).
"""
import re
import logging

logger = logging.getLogger(__name__)


def extract_all(text: str) -> dict:
    """Extract all intelligence from a text string."""
    return {
        "phoneNumbers": extract_phone_numbers(text),
        "bankAccounts": extract_bank_accounts(text),
        "upiIds": extract_upi_ids(text),
        "phishingLinks": extract_urls(text),
        "emailAddresses": extract_emails(text),
    }


def merge_intelligence(existing: dict, new: dict) -> dict:
    """Merge new extracted intelligence into existing, deduplicating."""
    merged = {}
    for key in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"]:
        existing_list = existing.get(key, [])
        new_list = new.get(key, [])
        # Deduplicate while preserving order
        seen = set(existing_list)
        combined = list(existing_list)
        for item in new_list:
            if item not in seen:
                combined.append(item)
                seen.add(item)
        merged[key] = combined
    return merged


def extract_phone_numbers(text: str) -> list:
    """Extract phone numbers in various formats."""
    patterns = [
        # Indian format: +91-9876543210, +91 9876543210, 91-9876543210
        r'\+?91[-.\s]?\d{10}',
        r'\+?91[-.\s]?\d{5}[-.\s]?\d{5}',
        # International: +1-234-567-8901
        r'\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}',
        # Plain 10-digit Indian numbers
        r'\b[6-9]\d{9}\b',
        # Formatted: 98765-43210, (987) 654-3210
        r'\(?\d{3,5}\)?[-.\s]?\d{3,5}[-.\s]?\d{4,5}',
    ]
    
    results = set()
    for pattern in patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            cleaned = match.strip()
            # Must have at least 10 digits total
            digits_only = re.sub(r'\D', '', cleaned)
            if 10 <= len(digits_only) <= 15:
                results.add(cleaned)
    
    return list(results)


def extract_bank_accounts(text: str) -> list:
    """Extract bank account numbers (10-18 digit sequences)."""
    # Look for explicit bank account patterns
    patterns = [
        # "account number 1234567890123456"
        r'(?:account|a/c|acct)[\s#:.-]*(?:no|number|num)?[\s#:.-]*(\d{10,18})',
        # "A/C: 1234567890123456"
        r'(?:A/C|ACC)[\s:.-]*(\d{10,18})',
        # Standalone long digit sequences (12-18 digits likely bank accounts)
        r'\b(\d{12,18})\b',
        # 10-11 digit sequences that appear near banking keywords
        r'\b(\d{10,11})\b',
    ]
    
    results = set()
    text_lower = text.lower()
    
    for i, pattern in enumerate(patterns):
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            digits = re.sub(r'\D', '', match)
            # For shorter sequences (10-11 digits), only include if banking context
            if len(digits) < 12:
                banking_keywords = ['account', 'a/c', 'bank', 'deposit', 'transfer', 'balance', 'acct']
                if not any(kw in text_lower for kw in banking_keywords):
                    continue
            if 10 <= len(digits) <= 18:
                results.add(digits)
    
    # Remove any that are clearly phone numbers
    phone_numbers = set(re.sub(r'\D', '', p) for p in extract_phone_numbers(text))
    results = results - phone_numbers
    
    return list(results)


def extract_upi_ids(text: str) -> list:
    """Extract UPI IDs (format: name@bank)."""
    # UPI IDs look like: user@bankname, name.surname@upi
    # Different from emails: UPI uses bank names not domains with TLDs
    pattern = r'\b([\w.-]+@(?:upi|ybl|paytm|oksbi|okicici|okaxis|okhdfcbank|apl|ibl|sbi|icici|hdfc|axis|kotak|bob|pnb|canara|union|boi|uco|idbi|indian|central|baroda|dbs|rbl|indus|yes|freecharge|mobikwik|jio|airtel|phonepe|gpay|amazonpay|fakebank|fakeupi|[a-z]{2,8}))\b'
    
    matches = re.findall(pattern, text, re.IGNORECASE)
    results = set()
    for match in matches:
        cleaned = match.strip().lower()
        # Exclude obvious emails (those with .com, .org, etc.)
        if not re.search(r'\.\w{2,4}$', cleaned):
            results.add(match.strip())
    
    return list(results)


def extract_urls(text: str) -> list:
    """Extract suspicious URLs/phishing links."""
    pattern = r'https?://[^\s,)\"\'<>]+'
    
    matches = re.findall(pattern, text, re.IGNORECASE)
    results = set()
    for match in matches:
        # Clean trailing punctuation
        cleaned = match.rstrip('.,;:!?)')
        if len(cleaned) > 10:  # Skip very short URLs
            results.add(cleaned)
    
    return list(results)


def extract_emails(text: str) -> list:
    """Extract email addresses."""
    pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    
    matches = re.findall(pattern, text, re.IGNORECASE)
    results = set()
    for match in matches:
        # Ensure it has a proper TLD (not a UPI ID)
        if re.search(r'\.(com|org|net|in|co|io|gov|edu|info|biz|me|xyz|online|site|tech|app|dev|cloud)\b', match, re.IGNORECASE):
            results.add(match.strip())
    
    return list(results)
