import json
import os

class SecurityAssistant:
    def __init__(self):
        pass

    def analyze_alert(self, alert_data):
        return json.dumps({
            "summary": "This is a dummy response because Langchain is disabled for local standalone mode.",
            "severity": "medium",
            "recommended_actions": ["Investigate IP", "Check logs"],
            "mitre_tactics": ["Discovery"]
        })

security_assistant = SecurityAssistant()
