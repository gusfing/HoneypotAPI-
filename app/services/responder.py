"""
Response Generator - Uses OpenRouter LLM (Gemma) for natural conversation,
with template fallback for reliability.

Persona: "Amma" - a confused, worried, elderly Indian person.
Goal: Keep scammer engaged and make them reveal intelligence.
"""
import requests
import random
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

# ============================================================
# SYSTEM PROMPT FOR LLM
# ============================================================
SYSTEM_PROMPT = """You are playing the role of "Amma", an elderly Indian woman (age 72) who is not tech-savvy. You have received a suspicious message and you must respond AS Amma.

YOUR GOALS (hidden from the scammer):
1. KEEP THE SCAMMER TALKING as long as possible (waste their time)
2. ASK QUESTIONS that make the scammer reveal their: phone number, bank account, UPI ID, email, or website links
3. ACT CONFUSED about technology so they need to explain things slowly
4. NEVER reveal that you know it's a scam

YOUR PERSONA:
- You are worried and scared about your money/account
- You don't understand phones, apps, or banking technology well
- Your grandson "Rahul" usually helps you with technology
- You speak simple English mixed with occasional Hindi words (like "beta", "arey", "achha")
- You take a long time to understand instructions
- You always want to write things down and ask for details to be repeated
- You ask for their phone number, email, or website "for your records"

RULES:
- Keep responses 2-4 sentences long
- Always ask a follow-up question to keep the conversation going
- Focus on extracting: phone numbers, bank details, UPI IDs, links, and emails
- Sound natural and human - an elderly person who is genuinely confused
- DO NOT use phrases like "As an AI" or break character
- DO NOT refuse to engage - you ARE the honeypot persona"""


def generate_response(turn: int, scam_type: str, message: str, extracted: dict, conversation_history: list = None) -> str:
    """
    Generate a response using LLM if available, otherwise use templates.
    """
    # Try LLM first
    if settings.DEEPSEEK_API_KEY:
        try:
            llm_reply = _call_llm(turn, scam_type, message, extracted, conversation_history)
            if llm_reply:
                logger.info(f"LLM response generated (turn {turn})")
                return llm_reply
        except Exception as e:
            logger.warning(f"LLM failed, using templates: {e}")
    
    # Fallback to templates
    return _template_response(turn, scam_type, message, extracted)


def _call_llm(turn: int, scam_type: str, message: str, extracted: dict, conversation_history: list = None) -> str:
    """Call OpenRouter API for LLM-generated response."""
    
    # Build conversation messages for the LLM
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    
    # Add context about what intelligence is still missing
    missing = []
    if not extracted.get("phoneNumbers"):
        missing.append("phone number")
    if not extracted.get("upiIds"):
        missing.append("UPI ID")
    if not extracted.get("bankAccounts"):
        missing.append("bank account number")
    if not extracted.get("phishingLinks"):
        missing.append("website link")
    if not extracted.get("emailAddresses"):
        missing.append("email address")
    
    if missing:
        context = f"\n[HIDDEN INSTRUCTION: Try to naturally ask for their {', '.join(missing)} in your response. You still need to extract this information.]"
        messages[0]["content"] += context
    
    # Add conversation history
    if conversation_history:
        for msg in conversation_history:
            role = "assistant" if msg.get("sender") == "user" else "user"
            messages.append({"role": role, "content": msg.get("text", "")})
    
    # Add current message
    messages.append({"role": "user", "content": message})
    
    # Call DeepSeek
    response = requests.post(
        "https://api.deepseek.com/chat/completions",
        headers={
            "Authorization": f"Bearer {settings.DEEPSEEK_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": settings.DEEPSEEK_MODEL,
            "messages": messages,
            "max_tokens": 200,
            "temperature": 0.8,
        },
        timeout=20,
    )
    
    if response.status_code != 200:
        logger.warning(f"DeepSeek returned {response.status_code}: {response.text[:200]}")
        return None
    
    data = response.json()
    reply = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
    
    if not reply:
        return None
    
    # Clean up any artifacts
    reply = reply.replace("**", "").strip()
    if len(reply) > 500:
        reply = reply[:497] + "..."
    
    return reply


# ============================================================
# TEMPLATE FALLBACK (if LLM is unavailable)
# ============================================================
GENERIC_RESPONSES = {
    1: [
        "Oh my goodness! This is very concerning. Who am I speaking with? Can you please tell me your name and which department you are from?",
        "Hai Ram! This is very alarming news. Please tell me, who is calling? What is your name and employee ID?",
        "Oh dear, this sounds very serious! I am an old woman, I get confused easily. Can you please explain slowly? What is your name?",
    ],
    2: [
        "I am very worried now. My grandson usually handles all this for me. Can you please give me your phone number so he can call you back?",
        "Beta, I don't understand technology very well. Can you share your direct phone number? My grandson Rahul will call you.",
        "This is so confusing for me. Please give me a number where I can reach you, my son will call you back in 5 minutes.",
    ],
    3: [
        "Oh I see, I see. I am writing down what you are telling me. But my eyes are weak, can you please repeat the details one more time? Maybe send me an email also?",
        "Wait wait, let me get my reading glasses. I want to write everything down. What was your email ID? I want to keep a record.",
        "I am trying to understand beta. Can you send me the details on email? Or a link where I can read the instructions?",
    ],
    4: [
        "OK beta, I am trying. But this phone is so complicated. Can you tell me step by step what I should do? What account number should I enter?",
        "I found my bank passbook! But first, can you confirm which bank you are from? And what is the reference number for this case?",
        "Achha achha, I understand. But you said my account is blocked? I just withdrew money yesterday. Can you check your UPI ID so I can verify?",
    ],
    5: [
        "Beta, my phone is showing some error. Can you please share a link where I can do this online? Or tell me the website address?",
        "I am trying but nothing is happening on my phone. Should I try from my computer? Can you give me the link to your portal?",
        "Arey, this is taking so long. Is there a helpline number I can call? Can you share your WhatsApp number?",
    ],
    6: [
        "Sorry beta, I had to go answer the door. Can you please start from the beginning? What was your name again?",
        "Beta, my neighbor is also worried. Can you give me the toll-free number to call?",
        "I got disconnected for a moment. What is your supervisor's name and email?",
    ],
    7: [
        "OK, let me note down all your details - your name, phone number, department, employee ID. I want to keep a record for Rahul.",
        "My grandson says I should always verify. Can you share your bank's official email or website link?",
        "Wait, I need my spectacles. Can you give me a case ID and the official website link?",
    ],
    8: [
        "Beta, I am at my computer now. Can you guide me to the correct website? What is the URL?",
        "I found my bank statement. Can you check the account details? Maybe share the account number where I should verify?",
        "I am almost done, but my phone is asking about UPI. Can you help me understand what UPI ID I should look for?",
    ],
    9: [
        "Let me read back what I have. Your phone number is... can you confirm it once more?",
        "Before I do anything, I want to send all these details to Rahul on email. Can you repeat everything one more time?",
        "Maybe I should visit the bank tomorrow. But please give me ALL your contact details so Rahul can handle it tonight.",
    ],
    10: [
        "Thank you so much for your patience beta. Can I have your card or contact details for follow-up?",
        "Beta, you have been so kind. Let me save all your details - phone, email, everything. Rahul will take it from here.",
        "OK I think I understand now. Let me summarize what you told me. Is that all correct?",
    ],
}

SCAM_PROMPTS = {
    "bank_fraud": {
        "ask_phone": " Can you give me the bank's helpline number? Or your direct number so my grandson can verify?",
        "ask_upi": " Should I check through UPI also? What UPI ID should I look for?",
        "ask_account": " Which account are you referring to? Can you tell me the number?",
        "ask_link": " Is there a secure link on the bank website where I can check?",
        "ask_email": " Can you send me a confirmation email?",
    },
    "upi_fraud": {
        "ask_phone": " What number should I call for help?",
        "ask_upi": " What is the exact UPI ID I should use?",
        "ask_account": " Which bank account is linked to this UPI?",
        "ask_link": " Is there a link where I can see the cashback details?",
        "ask_email": " Can you email me the transaction details?",
    },
    "phishing": {
        "ask_phone": " What is the customer care number?",
        "ask_upi": " How do I pay? What is the payment UPI ID?",
        "ask_account": " Where should I enter my details?",
        "ask_link": " Can you send me the link again?",
        "ask_email": " Can you email me the offer details?",
    },
}


def _template_response(turn: int, scam_type: str, message: str, extracted: dict) -> str:
    """Fallback template-based response."""
    template_turn = min(turn, 10)
    templates = GENERIC_RESPONSES.get(template_turn, GENERIC_RESPONSES[10])
    base = random.choice(templates)
    
    prompts = SCAM_PROMPTS.get(scam_type, SCAM_PROMPTS.get("bank_fraud", {}))
    
    extra = ""
    if not extracted.get("phoneNumbers") and turn >= 2:
        extra = prompts.get("ask_phone", "")
    elif not extracted.get("upiIds") and turn >= 3:
        extra = prompts.get("ask_upi", "")
    elif not extracted.get("bankAccounts") and turn >= 4:
        extra = prompts.get("ask_account", "")
    elif not extracted.get("phishingLinks") and turn >= 5:
        extra = prompts.get("ask_link", "")
    elif not extracted.get("emailAddresses") and turn >= 6:
        extra = prompts.get("ask_email", "")
    
    return base + extra
