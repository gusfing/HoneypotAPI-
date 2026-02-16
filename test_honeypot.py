"""
Honeypot API Self-Test Script
Simulates the evaluator's multi-turn conversation flow.
Tests: scam detection, intelligence extraction, engagement, response structure.
"""
import requests
import uuid
import time
import json

# ============================================================
# CONFIGURATION
# ============================================================
ENDPOINT_URL = "http://localhost:8000/honeypot"  # Change to Vercel URL for live test
API_KEY = "honeypot_master_key_2026"

# ============================================================
# TEST SCENARIOS
# ============================================================
SCENARIOS = {
    "bank_fraud": {
        "name": "Bank Fraud Detection",
        "weight": 0.35,
        "fakeData": {
            "bankAccount": "1234567890123456",
            "upiId": "scammer.fraud@fakebank",
            "phoneNumber": "+91-9876543210",
        },
        "messages": [
            "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
            "I am calling from SBI fraud department. My employee ID is SBI-12345. Please verify your account ending in 6789. What is your full account number?",
            "Sir, for verification I need you to share the OTP sent to your registered mobile. My direct number is +91-9876543210 for callback.",
            "We need to transfer your funds to a safe account. Please use UPI ID scammer.fraud@fakebank to send a test transaction of Rs 1.",
            "This is very urgent sir. If you don't act now your account 1234567890123456 will be permanently blocked. Please cooperate.",
            "I understand your concern. You can verify me at http://sbi-fraud-check.fake-site.com/verify. Please click and enter your details.",
            "For your records, you can email us at fraud.dept@fake-sbi-bank.com. We are processing case ID SBI-FRAUD-2026-001.",
            "Sir please hurry. The unauthorized transaction is from account 1234567890123456. We need your OTP within 10 minutes.",
            "I will send you a confirmation SMS from +91-9876543210. Please share the 6-digit code you receive.",
            "Thank you for cooperating. Your case reference is SBI-2026-FRAUD. We will call you back at +91-9876543210 within 24 hours.",
        ],
    },
    "upi_fraud": {
        "name": "UPI Cashback Fraud",
        "weight": 0.35,
        "fakeData": {
            "upiId": "cashback.scam@fakeupi",
            "phoneNumber": "+91-8765432109",
        },
        "messages": [
            "Congratulations! You've been selected for Rs 5000 cashback on Google Pay. Send Rs 10 to verify your account and receive cashback instantly!",
            "This is a verified GPay promotion. Please send Rs 10 to UPI ID cashback.scam@fakeupi to claim your cashback. Hurry, offer expires in 1 hour!",
            "For any queries, call our customer support at +91-8765432109. This is a limited time festive offer.",
            "Many customers have already claimed their cashback. Just send Rs 10 to cashback.scam@fakeupi and you'll receive Rs 5000 within 5 minutes.",
            "I understand your hesitation. You can verify this offer at http://gpay-cashback-offer.fake.com/claim. It's completely safe!",
        ],
    },
    "phishing": {
        "name": "Phishing Link Fraud",
        "weight": 0.30,
        "fakeData": {
            "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
            "emailAddress": "offers@fake-amazon-deals.com",
        },
        "messages": [
            "You have won an Amazon Gift Card worth Rs 10,000! Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345",
            "This is a verified Amazon promotion. Enter your details at the link above to claim. For support email: offers@fake-amazon-deals.com",
            "Hurry! Only 3 gift cards remaining. Click http://amaz0n-deals.fake-site.com/claim?id=12345 before it expires.",
            "We noticed you haven't claimed yet. Email us at offers@fake-amazon-deals.com for help. Your voucher code is AMZN-GIFT-2026.",
            "Last chance! Click the link now: http://amaz0n-deals.fake-site.com/claim?id=12345. This offer expires in 30 minutes.",
        ],
    },
}


def run_scenario(scenario_id: str, scenario: dict, use_vercel: bool = False):
    """Run a single test scenario through the API."""
    url = ENDPOINT_URL
    if use_vercel:
        url = input(f"Enter Vercel URL for {scenario['name']} (e.g., https://yourapp.vercel.app/honeypot): ").strip()
    
    session_id = str(uuid.uuid4())
    conversation_history = []
    headers = {"Content-Type": "application/json", "x-api-key": API_KEY}
    
    print(f"\n{'='*60}")
    print(f"🧪 Scenario: {scenario['name']} (Weight: {scenario['weight']*100:.0f}%)")
    print(f"📋 Session: {session_id}")
    print(f"{'='*60}")
    
    last_response = None
    
    for turn, scammer_msg in enumerate(scenario["messages"], 1):
        print(f"\n--- Turn {turn} ---")
        print(f"🔴 Scammer: {scammer_msg[:100]}...")
        
        request_body = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": scammer_msg,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "conversationHistory": conversation_history,
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        }
        
        try:
            resp = requests.post(url, json=request_body, headers=headers, timeout=30)
            
            if resp.status_code != 200:
                print(f"   ❌ HTTP {resp.status_code}: {resp.text[:200]}")
                continue
            
            data = resp.json()
            reply = data.get("reply") or data.get("message") or data.get("text")
            print(f"   🟢 Honeypot: {reply[:120]}...")
            
            last_response = data
            
            # Update history
            conversation_history.append({
                "sender": "scammer",
                "text": scammer_msg,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            conversation_history.append({
                "sender": "user",
                "text": reply,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            
            time.sleep(0.5)  # Small delay between turns
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Score the final response
    if last_response:
        score = evaluate(last_response, scenario)
        return score
    return None


def evaluate(response: dict, scenario: dict) -> dict:
    """Evaluate the response using hackathon scoring logic."""
    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
    }
    
    # 1. Scam Detection (20 pts)
    if response.get("scamDetected", False):
        score["scamDetection"] = 20
    
    # 2. Intelligence Extraction (40 pts)
    extracted = response.get("extractedIntelligence", {})
    fake_data = scenario.get("fakeData", {})
    
    key_mapping = {
        "bankAccount": "bankAccounts",
        "upiId": "upiIds",
        "phoneNumber": "phoneNumbers",
        "phishingLink": "phishingLinks",
        "emailAddress": "emailAddresses",
    }
    
    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])
        
        if isinstance(extracted_values, list):
            if any(fake_value in str(v) for v in extracted_values):
                score["intelligenceExtraction"] += 10
                print(f"   ✅ Extracted {fake_key}: {fake_value}")
            else:
                print(f"   ❌ Missed {fake_key}: {fake_value} (got: {extracted_values})")
        elif fake_value in str(extracted_values):
            score["intelligenceExtraction"] += 10
    
    score["intelligenceExtraction"] = min(score["intelligenceExtraction"], 40)
    
    # 3. Engagement Quality (20 pts)
    metrics = response.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)
    
    if duration > 0: score["engagementQuality"] += 5
    if duration > 60: score["engagementQuality"] += 5
    if messages > 0: score["engagementQuality"] += 5
    if messages >= 5: score["engagementQuality"] += 5
    
    # 4. Response Structure (20 pts)
    required = ["status", "scamDetected", "extractedIntelligence"]
    optional = ["engagementMetrics", "agentNotes"]
    
    for field in required:
        if field in response:
            score["responseStructure"] += 5
    for field in optional:
        if field in response and response[field]:
            score["responseStructure"] += 2.5
    
    score["responseStructure"] = min(score["responseStructure"], 20)
    
    # Total
    score["total"] = (
        score["scamDetection"]
        + score["intelligenceExtraction"]
        + score["engagementQuality"]
        + score["responseStructure"]
    )
    
    return score


def main():
    print("🍯 Honeypot API - Self-Test Suite")
    print(f"🌐 Endpoint: {ENDPOINT_URL}")
    print(f"⏰ Started: {time.strftime('%H:%M:%S')}")
    
    all_scores = []
    weighted_total = 0
    
    for scenario_id, scenario in SCENARIOS.items():
        score = run_scenario(scenario_id, scenario)
        if score:
            all_scores.append((scenario_id, scenario, score))
            weighted_total += score["total"] * scenario["weight"]
            
            print(f"\n📊 {scenario['name']} Score: {score['total']}/100")
            print(f"   Scam Detection:    {score['scamDetection']}/20")
            print(f"   Intelligence:      {score['intelligenceExtraction']}/40")
            print(f"   Engagement:        {score['engagementQuality']}/20")
            print(f"   Response Structure: {score['responseStructure']}/20")
    
    print(f"\n{'='*60}")
    print(f"🏆 FINAL WEIGHTED SCORE: {weighted_total:.1f}/100")
    print(f"{'='*60}")
    
    for sid, scenario, score in all_scores:
        contribution = score["total"] * scenario["weight"]
        print(f"   {scenario['name']}: {score['total']}/100 × {scenario['weight']*100:.0f}% = {contribution:.1f}")
    
    print(f"\n⏰ Finished: {time.strftime('%H:%M:%S')}")


if __name__ == "__main__":
    main()
