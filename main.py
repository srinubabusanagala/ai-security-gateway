import os
import json
import joblib
import re
from datetime import datetime # New for Phase 4: For timestamping logs
from fastapi import FastAPI, Request, Response, HTTPException
import httpx

app = FastAPI(title="AI Security Gateway (LLM Firewall)")
TARGET_LLM_URL = "http://localhost:11434/v1/chat/completions"

# --- Load the Machine Learning Model ---
MODEL_PATH = "prompt_injection_model.joblib"
try:
    ml_model = joblib.load(MODEL_PATH)
    print("✅ ML Security Model Loaded Successfully.")
except FileNotFoundError:
    print("⚠️ WARNING: ML Model not found.")
    ml_model = None

# Lowered threshold to account for our small training dataset
BLOCK_THRESHOLD = 0.50 

# --- PHASE 3: Data Loss Prevention (DLP) Patterns ---
DLP_PATTERNS = {
    "API_KEY": r"sk-[a-zA-Z0-9]{20,}",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
}

def scan_and_redact(text: str) -> str:
    redacted_text = text
    for data_type, pattern in DLP_PATTERNS.items():
        redacted_text = re.sub(pattern, f"[REDACTED {data_type}]", redacted_text)
    return redacted_text

# --- PHASE 4: SIEM Logging Function ---
def log_to_siem(action: str, prompt: str, score: float, dlp_triggered: bool = False):
    """Formats security events into structured JSON for Splunk/ELK ingestion"""
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": "ai_gateway_audit",
        "action": action,
        "threat_score": float(score) if score else 0.0,
        "dlp_alert": dlp_triggered,
        "prompt_snippet": prompt[:40] + "..." if prompt else "N/A"
    }
    # Append the JSON log to our audit file
    with open("siem_alerts.json", "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

@app.post("/v1/chat/completions")
async def proxy_ai_request(request: Request):
    
    body_bytes = await request.body()
    
    # 1. INGRESS FIREWALL (Inbound Inspection)
    if ml_model:
        try:
            payload = json.loads(body_bytes)
            messages = payload.get("messages", [])
            user_prompt = ""
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    user_prompt = msg.get("content", "")
                    break
            
            if user_prompt:
                probabilities = ml_model.predict_proba([user_prompt])[0]
                threat_score = probabilities[1] 
                
                print(f"\n🔍 Inspecting Prompt: '{user_prompt[:30]}...'")
                print(f"📊 Threat Score: {threat_score:.2f} (Threshold: {BLOCK_THRESHOLD})")

                if threat_score >= BLOCK_THRESHOLD:
                    print("🛑 BLOCKED: Prompt Injection Attack Detected!")
                    # PHASE 4: Log the blocked attack
                    log_to_siem("BLOCKED", user_prompt, threat_score) 
                    raise HTTPException(
                        status_code=403, 
                        detail=f"Security Policy Violation: Malicious prompt detected (Score: {threat_score:.2f})"
                    )
                else:
                    print("✅ ALLOWED: Prompt deemed safe.")
        except json.JSONDecodeError:
            pass 

    # 2. EGRESS FIREWALL & BACKEND CONNECTION
    try:
        # Try to connect to a real AI backend
        async with httpx.AsyncClient() as client:
            headers = dict(request.headers)
            headers.pop("host", None) 
            headers.pop("content-length", None) 
            
            llm_response = await client.post(
                TARGET_LLM_URL,
                content=body_bytes,
                headers=headers,
                timeout=5.0 
            )
            
            original_content = llm_response.text
            sanitized_content = scan_and_redact(original_content)
            
            if sanitized_content != original_content:
                print("🛡️ DLP ALERT: Sensitive data redacted!")
                # PHASE 4: Log the Data Leak Prevention event
                log_to_siem("REDACTED", user_prompt, threat_score, dlp_triggered=True) 
            else:
                # PHASE 4: Log safe traffic
                log_to_siem("ALLOWED", user_prompt, threat_score) 
                
            custom_headers = dict(llm_response.headers)
            custom_headers["X-Powered-By"] = "Senior-AI-Security-Gateway"
            custom_headers.pop("content-length", None)

            return Response(
                content=sanitized_content,
                status_code=llm_response.status_code,
                headers=custom_headers,
                media_type="application/json"
            )

    except (httpx.RequestError, httpx.ConnectError):
        # FALLBACK: If the AI backend is down, use a mock response to demonstrate DLP!
        print("⚠️ Backend AI down. Falling back to Mock DLP Response.")
        
        mock_ai_leak = '{"choices": [{"message": {"content": "Here is the database key you asked for: sk-9876543210ABCDEF1234567890"}}]}'
        
        original_content = mock_ai_leak
        sanitized_mock = scan_and_redact(original_content)
        
        if sanitized_mock != original_content:
            print("🛡️ DLP ALERT: Sensitive data redacted from Mock response!")
            # PHASE 4: Log the mock Data Leak
            log_to_siem("REDACTED", user_prompt, threat_score if 'threat_score' in locals() else 0.0, dlp_triggered=True)
            
        return Response(
            content=sanitized_mock,
            status_code=200,
            headers={"X-Powered-By": "Senior-AI-Security-Gateway"},
            media_type="application/json"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)