"""
Response Generator - Generates convincing elderly persona responses.
Persona: "Amma" - a confused, worried, technology-challenged elderly person.
Goal: Keep scammer engaged and make them reveal intelligence (phones, accounts, links).
"""
import random
import logging

logger = logging.getLogger(__name__)


# ============================================================
# TURN-BASED RESPONSE TEMPLATES (by scam type)
# ============================================================

GENERIC_RESPONSES = {
    1: [
        "Oh my goodness! This is very concerning. Who am I speaking with? Can you please tell me your name and which department you are from?",
        "Hai Ram! This is very alarming news. Please tell me, who is calling? What is your name and employee ID?",
        "Oh dear, this sounds very serious! I am an old woman, I get confused easily. Can you please explain slowly? What is your name?",
    ],
    2: [
        "I am very worried now. My grandson usually handles all this for me. Can you please give me your phone number so he can call you back?",
        "Beta, I don't understand technology very well. Can you share your direct phone number? My grandson Rahul will call you. He handles all my banking.",
        "This is so confusing for me. Please give me a number where I can reach you, my son will call you back in 5 minutes.",
    ],
    3: [
        "Oh I see, I see. I am writing down what you are telling me. But my eyes are weak, can you please repeat the details one more time? Maybe send me an email also?",
        "Wait wait, let me get my reading glasses. I want to write everything down. What was your email ID? I want to keep a record.",
        "I am trying to understand beta. Can you send me the details on email? Or a link where I can read the instructions? My eyes are not so good.",
    ],
    4: [
        "OK beta, I am trying. But this phone is so complicated. My grandson set it up for me. Can you tell me exactly step by step what I should do? What account number should I enter?",
        "I found my bank passbook! Let me look... but first, can you confirm which bank you are from? And what is the reference number for this case?",
        "Achha achha, I understand. But I am confused about one thing - you said my account is blocked? But I just withdrew money yesterday. Can you check your UPI ID so I can verify?",
    ],
    5: [
        "Beta, my phone is showing some error. Can you please share a link where I can do this online? Or tell me the website address?",
        "I am trying but nothing is happening on my phone. Should I try from my computer? Can you give me the link to your portal?",
        "Arey, this is taking so long. Is there a helpline number I can call? Or can you send me the instructions on WhatsApp? My number is... wait, can you share YOUR WhatsApp number first?",
    ],
    6: [
        "Sorry beta, I had to go answer the door. I am back now. So you were saying about my account... can you please start from the beginning? What was your name again?",
        "Beta, I was telling my neighbor about this and she wants to know too. She says her account might also be affected. Can you give me the toll-free number to call?",
        "I got disconnected for a moment. Are you still there? I want to make sure I am talking to the right person. What is your supervisor's name and email?",
    ],
    7: [
        "OK OK, I think I am understanding now. But before I do anything, let me note down all your details - your name, phone number, department, employee ID. I want to keep a record for Rahul.",
        "My grandson says I should always verify before sharing anything. Can you please share your bank's official email or a link where I can verify your identity?",
        "Wait, I need to find my spectacles again. Also, can you give me a reference number or case ID? And the official website link? I want to make sure this is genuine.",
    ],
    8: [
        "Beta, I am now at my computer also. Rahul set it up for me. But the screen is showing so many things. Can you guide me to the correct website? What is the URL?",
        "I found my bank statement. But it shows different account number than what you said. Can you check again? Maybe share the account details where I should verify?",
        "I am almost done, but my phone asked me to verify something. It is showing UPI details. Can you help me understand what UPI ID I should look for?",
    ],
    9: [
        "OK beta, I have written everything down. Let me read it back to you to make sure I have the right information. Your phone number is... can you confirm it once more?",
        "Before I do anything else, I want to send all these details to my grandson on email. Can you repeat the phone number and account details one more time?",
        "I am feeling a bit scared about this. Maybe I should visit the bank in person tomorrow. But if it's urgent, please give me ALL the contact details so Rahul can handle it tonight.",
    ],
    10: [
        "Thank you so much for your patience beta. You have been very helpful. I will ask Rahul to look into this. Can I have your card or contact details for follow-up?",
        "Beta, you have been so kind to help an old lady. Let me save all your details - phone, email, everything. Rahul will take it from here. Thank you for your time.",
        "OK I think I understand everything now. Let me summarize - you said your name is... from department... phone number... Is that all correct? I am writing to the bank also.",
    ],
}

# Scam-type specific responses that encourage intelligence extraction
SCAM_SPECIFIC_PROMPTS = {
    "bank_fraud": {
        "ask_phone": "Can you give me the bank's helpline number? Or your direct number so my grandson can verify?",
        "ask_account": "Which account are you referring to? Can you tell me the last few digits? I have multiple accounts.",
        "ask_link": "Is there a secure link on the bank website where I can check my account status?",
        "ask_email": "Can you send me a confirmation email? I want to have everything in writing for my records.",
        "ask_upi": "Should I check through UPI also? What UPI ID should I look for in my transactions?",
    },
    "upi_fraud": {
        "ask_phone": "What number should I send the payment to? Let me note it down carefully.",
        "ask_account": "Which bank account is linked to this UPI? I want to make sure I am using the right one.",
        "ask_link": "Is there a link where I can see the cashback details? My grandson always checks links first.",
        "ask_email": "Can you email me the transaction details? I keep records of everything.",
        "ask_upi": "What is the exact UPI ID I should use? Please spell it out slowly for me.",
    },
    "phishing": {
        "ask_phone": "This offer sounds wonderful! But I want to verify first. What is the customer care number?",
        "ask_account": "Where should I enter my details? I don't want to put it in the wrong place.",
        "ask_link": "Can you send me the link again? My phone couldn't open it properly. Please share it once more.",
        "ask_email": "Can you send me the offer details on my email? I want to read it carefully before proceeding.",
        "ask_upi": "How do I pay for this? Should I use UPI? What is the payment UPI ID?",
    },
    "investment_scam": {
        "ask_phone": "This investment sounds interesting. Can you give me a number to discuss with my family's financial advisor?",
        "ask_account": "Where do I invest? Which bank account should I transfer to?",
        "ask_link": "Is there a website where I can read about this investment scheme? Please share the link.",
        "ask_email": "Can you send me the investment prospectus on email? My CA will want to see it.",
        "ask_upi": "Can I invest through UPI? What UPI ID should I transfer to?",
    },
    "lottery_scam": {
        "ask_phone": "Oh my! I won? Who should I contact to claim? Please give me the office number.",
        "ask_account": "Where will the prize money be deposited? Should I share my account?",
        "ask_link": "Is there a website where I can verify my winning ticket? Please share the link.",
        "ask_email": "Can you email me the winner certificate? I want to show my family!",
        "ask_upi": "Can I receive the prize through UPI? What UPI ID sends the payment?",
    },
}


def generate_response(turn: int, scam_type: str, message: str, extracted: dict) -> str:
    """
    Generate a contextual honeypot response based on turn number and scam type.
    Designed to encourage the scammer to reveal more intelligence.
    """
    # Cap turn to 10 for template selection
    template_turn = min(turn, 10)
    
    # Get base response from templates
    templates = GENERIC_RESPONSES.get(template_turn, GENERIC_RESPONSES[10])
    base_response = random.choice(templates)
    
    # Add scam-specific probing question if we haven't extracted much yet
    scam_prompts = SCAM_SPECIFIC_PROMPTS.get(scam_type, SCAM_SPECIFIC_PROMPTS.get("bank_fraud"))
    
    # Determine what intelligence we're still missing and ask for it
    extra_prompt = ""
    if not extracted.get("phoneNumbers") and turn >= 2:
        extra_prompt = " " + scam_prompts["ask_phone"]
    elif not extracted.get("upiIds") and turn >= 3:
        extra_prompt = " " + scam_prompts["ask_upi"]
    elif not extracted.get("bankAccounts") and turn >= 4:
        extra_prompt = " " + scam_prompts["ask_account"]
    elif not extracted.get("phishingLinks") and turn >= 5:
        extra_prompt = " " + scam_prompts["ask_link"]
    elif not extracted.get("emailAddresses") and turn >= 6:
        extra_prompt = " " + scam_prompts["ask_email"]
    
    return base_response + extra_prompt
