# Honeypot API 🍯

## 🏆 Impact AI Hackathon 2026

A conversational AI honeypot that engages scammers, detects fraud, and extracts intelligence in real-time.

## 📖 Description

This API acts as a **digital honeypot** — it impersonates a vulnerable person (confused elderly individual) to:
1. **Detect scams** using keyword/pattern analysis across 5+ fraud categories
2. **Extract intelligence** (phone numbers, bank accounts, UPI IDs, phishing links, emails)
3. **Engage scammers** in realistic multi-turn conversations to waste their time
4. **Report findings** with structured analysis and engagement metrics

## 🧠 Approach & Strategy

### How We Detect Scams
- **Keyword Analysis**: 80+ scam keywords across bank fraud, UPI fraud, phishing, investment scams, and lottery scams
- **Urgency Detection**: Identifies pressure tactics ("urgent", "immediately", "act fast")
- **Pattern Matching**: Classifies scam type based on weighted keyword scoring
- **Always-On**: Treats all incoming conversations as potential scams (honeypot assumption)

### How We Extract Intelligence
- **Regex Engine**: Robust pattern matching for:
  - 📞 Phone numbers (Indian +91 format, international, 10-digit)
  - 🏦 Bank account numbers (10-18 digit sequences with context)
  - 💳 UPI IDs (word@bank format, 30+ Indian bank suffixes)
  - 🔗 Phishing URLs (HTTP/HTTPS links)
  - 📧 Email addresses (with TLD validation)
- **Cumulative Scanning**: Extracts from both current message AND full conversation history
- **Deduplication**: Intelligent merging prevents double-counting

### How We Maintain Engagement
- **Persona**: "Amma" — a confused, worried, elderly person who:
  - Asks clarifying questions to stall
  - Requests phone numbers, email IDs, and links "for verification"
  - Pretends to need her grandson's help
  - Acts confused about technology
- **10-Turn Templates**: Context-aware responses for each conversation turn
- **Intelligence-Driven Probing**: Asks for missing intelligence types (if no phone extracted yet, specifically asks for it)

## 🛠 Tech Stack
- **Language**: Python 3.9+
- **Framework**: FastAPI
- **Deployment**: Vercel Serverless
- **Key Libraries**: Pydantic, python-dotenv
- **AI/ML**: Rule-based NLP (no external API dependencies for reliability)

## 🚀 Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/gusfing/HoneypotAPI.git
cd HoneypotAPI
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Set environment variables
```bash
cp .env.example .env
# Edit .env with your API key
```

### 4. Run the application
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 📡 API Endpoint

- **URL**: `POST /honeypot`
- **Authentication**: `x-api-key` header
- **Content-Type**: `application/json`

### Request Format
```json
{
  "sessionId": "uuid-string",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your account has been compromised...",
    "timestamp": "2026-02-16T10:30:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response Format
```json
{
  "status": "success",
  "reply": "Oh my! This is very concerning. Who is this?",
  "scamDetected": true,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["1234567890123456"],
    "upiIds": ["scammer@fakebank"],
    "phishingLinks": [],
    "emailAddresses": []
  },
  "engagementMetrics": {
    "totalMessagesExchanged": 6,
    "engagementDurationSeconds": 120
  },
  "agentNotes": "Scam Type: bank_fraud (confidence: 0.95)..."
}
```

## 🧪 Testing

Run the included self-test script:
```bash
python test_honeypot.py
```

This simulates 3 scenarios (bank fraud, UPI fraud, phishing) with 10-turn conversations and scores using the hackathon rubric.

## 📂 Project Structure
```
├── api/
│   └── index.py            # Vercel serverless entry
├── app/
│   ├── main.py              # FastAPI app + /honeypot endpoint
│   ├── core/
│   │   └── config.py        # Settings
│   └── services/
│       ├── extractor.py     # Intelligence extraction (regex)
│       ├── detector.py      # Scam type classification
│       ├── responder.py     # Response generation (persona)
│       └── session.py       # Session management
├── test_honeypot.py         # Self-test script
├── requirements.txt
├── vercel.json
└── README.md
```

## ⚖️ Compliance & Ethics

- **Original Work**: Developed specifically for Impact AI Hackathon 2026
- **No Hardcoding**: Uses generic pattern matching, not test-specific responses
- **Privacy**: No data stored persistently — all analysis is in-memory
- **License**: MIT License

## 👨‍💻 Author
**Kunal Sharma**
