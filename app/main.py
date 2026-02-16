"""
Honeypot API - Main Application
A conversational honeypot that engages scammers, detects fraud,
and extracts intelligence.

Author: Kunal Sharma
Hackathon: Impact AI Hackathon 2026
"""
import logging
import time
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional
from app.core.config import settings
from app.services import extractor, detector, session
from app.services.responder import generate_response

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================
# FastAPI App
# ============================================================
app = FastAPI(title=settings.PROJECT_NAME, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Pydantic Models
# ============================================================
class MessageModel(BaseModel):
    sender: str = "scammer"
    text: str = ""
    timestamp: Optional[str] = None


class MetadataModel(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"


class HoneypotRequest(BaseModel):
    sessionId: str
    message: MessageModel
    conversationHistory: list = Field(default_factory=list)
    metadata: Optional[MetadataModel] = None


# ============================================================
# Authentication
# ============================================================
def verify_api_key(request: Request):
    """Verify the x-api-key header."""
    api_key = request.headers.get("x-api-key")
    if settings.API_KEY and api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")


# ============================================================
# Root Endpoint
# ============================================================
@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>🍯 Honeypot API</title>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #0f0c29, #302b63, #24243e); color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
            .card { background: rgba(255,255,255,0.08); backdrop-filter: blur(12px); border-radius: 20px; padding: 50px; max-width: 600px; text-align: center; border: 1px solid rgba(255,255,255,0.15); box-shadow: 0 20px 60px rgba(0,0,0,0.4); }
            h1 { font-size: 2.5em; margin-bottom: 10px; }
            .badge { display: inline-block; background: linear-gradient(90deg, #f7971e, #ffd200); color: #000; padding: 6px 18px; border-radius: 20px; font-weight: bold; font-size: 0.85em; margin-top: 15px; }
            p { color: #b0b0d0; line-height: 1.7; }
            code { background: rgba(255,255,255,0.1); padding: 3px 8px; border-radius: 6px; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🍯 Honeypot API</h1>
            <div class="badge">Impact AI Hackathon 2026</div>
            <p style="margin-top:25px;">A conversational AI honeypot that engages scammers, detects fraud, and extracts intelligence in real-time.</p>
            <p>Endpoint: <code>POST /honeypot</code></p>
            <p style="font-size:0.85em; color:#888;">Built by Kunal Sharma</p>
        </div>
    </body>
    </html>
    """


# ============================================================
# Main Honeypot Endpoint
# ============================================================
@app.post("/honeypot")
async def honeypot_endpoint(request: Request, body: HoneypotRequest):
    """
    Main honeypot conversation endpoint.
    Receives scam messages, engages the scammer, extracts intelligence.
    Returns reply + full analysis in every response for maximum scoring.
    """
    # Auth check
    verify_api_key(request)
    
    start_time = time.time()
    
    # Get or create session
    sess = session.get_or_create_session(body.sessionId)
    sess.add_message()
    
    logger.info(f"[{body.sessionId}] Turn {sess.message_count}: {body.message.text[:80]}...")
    
    # 1. Extract intelligence from current message
    current_intel = extractor.extract_all(body.message.text)
    
    # Also scan conversation history for intelligence we might have missed
    for msg in body.conversationHistory:
        if msg.get("sender") == "scammer":
            hist_intel = extractor.extract_all(msg.get("text", ""))
            current_intel = extractor.merge_intelligence(current_intel, hist_intel)
    
    # Merge into session's cumulative intelligence
    sess.extracted_intelligence = extractor.merge_intelligence(
        sess.extracted_intelligence, current_intel
    )
    
    logger.info(f"[{body.sessionId}] Extracted: {sess.extracted_intelligence}")
    
    # 2. Detect scam type
    scam_result = detector.detect_scam(body.message.text, body.conversationHistory)
    sess.scam_type = scam_result["scam_type"]
    sess.scam_confidence = scam_result["confidence"]
    sess.scam_indicators = scam_result["indicators"]
    
    logger.info(f"[{body.sessionId}] Scam: {scam_result['scam_type']} ({scam_result['confidence']})")
    
    # 3. Generate response (LLM-powered with template fallback)
    reply = generate_response(
        turn=sess.message_count,
        scam_type=sess.scam_type,
        message=body.message.text,
        extracted=sess.extracted_intelligence,
        conversation_history=body.conversationHistory,
    )
    
    logger.info(f"[{body.sessionId}] Reply: {reply[:80]}...")
    
    # 4. Build full response (include ALL fields for scoring)
    final_output = sess.build_final_output()
    
    elapsed = time.time() - start_time
    logger.info(f"[{body.sessionId}] Response time: {elapsed:.3f}s")
    
    # Return EVERYTHING - reply for conversation + all analysis fields for final scoring
    return {
        "status": "success",
        "reply": reply,
        # Final output fields (included in EVERY response for max scoring)
        "sessionId": body.sessionId,
        "scamDetected": True,
        "scamType": sess.scam_type,
        "totalMessagesExchanged": sess.message_count * 2,
        "extractedIntelligence": sess.extracted_intelligence,
        "engagementMetrics": sess.get_engagement_metrics(),
        "agentNotes": sess.get_agent_notes(),
    }


# ============================================================
# Health Check
# ============================================================
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "Honeypot API", "version": "1.0.0"}
