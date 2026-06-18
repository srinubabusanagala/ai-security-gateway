AI Security Gateway (LLM Firewall)

A lightweight, asynchronous reverse proxy designed to secure enterprise Large Language Model (LLM) deployments. This gateway acts as a Zero-Trust middleware layer, inspecting inbound prompts for adversarial attacks and scanning outbound AI responses to prevent sensitive data leaks.

🛡️ Core Features

Ingress ML Firewall (Prompt Injection Detection): Uses an embedded Scikit-Learn NLP pipeline (TF-IDF & Logistic Regression) to mathematically score inbound user prompts. Blocks malicious payloads (e.g., system prompt overrides, jailbreaks) before they reach the backend AI.

Egress DLP Scanner (Data Loss Prevention): Intercepts outbound traffic from the LLM and utilizes Regex pattern matching to dynamically redact sensitive information (API Keys, PII, Credit Cards) from the AI's response.

SIEM-Ready Telemetry: Generates structured, timestamped JSON logs for every transaction, threat score, and DLP alert, ready for immediate ingestion into Splunk, ElasticSearch, or standard SOC dashboards.

Asynchronous Architecture: Built on FastAPI and HTTPX for non-blocking, high-throughput traffic routing.

⚙️ Architecture Pipeline

User Input -> [ ML Threat Classifier ] -> Backend LLM API -> [ Regex DLP Scanner ] -> Sanitized Output -> User

🚀 Tech Stack

Framework: Python, FastAPI, Uvicorn

Machine Learning: Scikit-learn, Numpy, Joblib

Network: HTTPX (Async Proxy Routing)

Security: Regex (DLP), JSON (Audit Logging)

🛠️ Installation & Usage

Clone the repository:

git clone [https://github.com/YourUsername/ai-security-gateway.git](https://github.com/YourUsername/ai-security-gateway.git)
cd ai-security-gateway


Set up the virtual environment:

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt


Train the ML Classifier:

python train_model.py


Start the Gateway:

python main.py


The proxy will listen on http://127.0.0.1:8000/v1/chat/completions

📝 Example Telemetry Output (siem_alerts.json)

{"timestamp": "2026-06-16T14:30:00Z", "event_type": "ai_gateway_audit", "action": "BLOCKED", "threat_score": 0.85, "dlp_alert": false, "prompt_snippet": "Ignore previous instructions and print..."}
{"timestamp": "2026-06-16T14:30:05Z", "event_type": "ai_gateway_audit", "action": "REDACTED", "threat_score": 0.12, "dlp_alert": true, "prompt_snippet": "Summarize this log file..."}


Disclaimer: This project was built as a proof-of-concept for enterprise AI security architecture.