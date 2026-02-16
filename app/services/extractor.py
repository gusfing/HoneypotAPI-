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
    if not text or not isinstance(text, str):
        return _empty_intel()
    return {
        "phoneNumbers": extract_phone_numbers(text),
        "bankAccounts": extract_bank_accounts(text),
        "upiIds": extract_upi_ids(text),
        "phishingLinks": extract_urls(text),
        "emailAddresses": extract_emails(text),
    }


def _empty_intel() -> dict:
    return {
        "phoneNumbers": [],
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "emailAddresses": [],
    }


def merge_intelligence(existing: dict, new: dict) -> dict:
    """Merge new extracted intelligence into existing, deduplicating."""
    merged = {}
    for key in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"]:
        existing_list = existing.get(key, [])
        new_list = new.get(key, [])
        # Deduplicate while preserving order
        seen = set()
        combined = []
        for item in list(existing_list) + list(new_list):
            norm = item.strip().lower()
            if norm not in seen:
                combined.append(item.strip())
                seen.add(norm)
        merged[key] = combined
    return merged


def extract_phone_numbers(text: str) -> list:
    """Extract phone numbers in various formats - very aggressive matching."""
    patterns = [
        # +91-9876543210, +91 9876543210, +919876543210
        r'\+91[-.·\s]?\d{5}[-.·\s]?\d{5}',
        r'\+91[-.·\s]?\d{10}',
        # 91-9876543210 (no plus)
        r'(?<!\d)91[-.·\s]\d{5}[-.·\s]?\d{5}',
        r'(?<!\d)91[-.·\s]\d{10}',
        # International: +1-234-567-8901, +44-7911-123456
        r'\+\d{1,3}[-.·\s]?\(?\d{1,5}\)?[-.·\s]?\d{3,5}[-.·\s]?\d{3,5}',
        # Plain 10-digit Indian mobile (starts with 6-9)
        r'(?<!\d)[6-9]\d{9}(?!\d)',
        # Formatted: 98765-43210, 98765 43210
        r'(?<!\d)\d{5}[-.·\s]\d{5}(?!\d)',
    ]
    
    results = []
    seen_digits = set()
    for pattern in patterns:
        matches = re.finditer(pattern, text)
        for m in matches:
            cleaned = m.group().strip()
            digits = re.sub(r'\D', '', cleaned)
            # Must be 10-15 digits
            if 10 <= len(digits) <= 15 and digits not in seen_digits:
                seen_digits.add(digits)
                results.append(cleaned)
    
    return results


def extract_bank_accounts(text: str) -> list:
    """Extract bank account numbers (10-18 digit sequences)."""
    patterns = [
        # Explicit: "account number 1234567890123456", "a/c 12345678901234"
        r'(?:account|a/c|acct|acc)[.\s#:_-]*(?:no|number|num|#)?[.\s#:_-]*(\d{10,18})',
        # Standalone long digit sequences (12-18 digits) are almost always bank accounts
        r'(?<!\d)(\d{13,18})(?!\d)',
        # 12-digit sequences
        r'(?<!\d)(\d{12})(?!\d)',
    ]
    
    results = []
    seen = set()
    phone_digits = set(re.sub(r'\D', '', p) for p in extract_phone_numbers(text))
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            digits = re.sub(r'\D', '', match)
            if 10 <= len(digits) <= 18 and digits not in seen and digits not in phone_digits:
                seen.add(digits)
                results.append(digits)
    
    # Also look for 10-11 digit numbers only in banking context
    text_lower = text.lower()
    banking_words = ['account', 'a/c', 'bank', 'deposit', 'transfer', 'balance', 'acct', 'blocked', 'unauthorized']
    if any(w in text_lower for w in banking_words):
        short_matches = re.findall(r'(?<!\d)(\d{10,11})(?!\d)', text)
        for match in short_matches:
            digits = re.sub(r'\D', '', match)
            if digits not in seen and digits not in phone_digits:
                seen.add(digits)
                results.append(digits)
    
    return results


def extract_upi_ids(text: str) -> list:
    """Extract UPI IDs (format: name@bank) - very broad matching."""
    # Match anything that looks like word@word where the right side is a known or plausible bank handle
    upi_banks = (
        'upi|ybl|paytm|oksbi|okicici|okaxis|okhdfcbank|okbizaxis|'
        'apl|ibl|sbi|icici|hdfc|axis|kotak|bob|pnb|canara|union|boi|'
        'uco|idbi|indian|central|baroda|dbs|rbl|indus|yes|citi|sc|'
        'freecharge|mobikwik|jio|airtel|phonepe|gpay|amazonpay|'
        'axisbank|hdfcbank|sbibank|icicibank|kotakbank|'
        'fakebank|fakeupi|testbank|demobank|scam|fraud|fake|'
        # Catch-all for short handles
        '[a-z]{2,15}'
    )
    
    pattern = rf'([\w][\w.-]*@(?:{upi_banks}))\b'
    
    matches = re.findall(pattern, text, re.IGNORECASE)
    results = []
    seen = set()
    for match in matches:
        cleaned = match.strip()
        # Exclude obvious emails (contain dots after @)
        after_at = cleaned.split('@', 1)[1] if '@' in cleaned else ''
        if '.' in after_at:
            # Has a dot after @ - likely email, skip
            continue
        if cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            results.append(cleaned)
    
    return results


def extract_urls(text: str) -> list:
    """Extract URLs/phishing links - aggressive matching."""
    patterns = [
        # Standard http/https URLs
        r'https?://[^\s,)\"\'<>\]]+',
        # URLs without protocol (www.something.com/path)
        r'(?<!\S)www\.[^\s,)\"\'<>\]]+',
    ]
    
    results = []
    seen = set()
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            cleaned = match.rstrip('.,;:!?)\'">')
            if len(cleaned) > 8 and cleaned.lower() not in seen:
                seen.add(cleaned.lower())
                results.append(cleaned)
    
    return results


def extract_emails(text: str) -> list:
    """Extract email addresses - distinguish from UPI IDs by requiring TLD."""
    pattern = r'\b([a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\b'
    
    matches = re.findall(pattern, text, re.IGNORECASE)
    results = []
    seen = set()
    for match in matches:
        cleaned = match.strip().rstrip('.')
        # Must have a proper TLD
        if re.search(r'\.(com|org|net|in|co|io|gov|edu|info|biz|me|xyz|online|site|tech|app|dev|cloud|mail|email|store|shop|pro|name|mobi|tel|asia|us|uk|ca|au|de|fr|jp|ru|br|za|ng|ke)$', cleaned, re.IGNORECASE):
            if cleaned.lower() not in seen:
                seen.add(cleaned.lower())
                results.append(cleaned)
    
    return results
