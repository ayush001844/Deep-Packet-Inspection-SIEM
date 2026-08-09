import os
from typing import Dict, Any
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.schema.output_parser import StrOutputParser
import json

load_dotenv()

# We support configuring base URL to allow fallback to local LLMs (e.g., Ollama)
# If OPENAI_API_BASE is set (e.g. http://localhost:11434/v1), we use it.
openai_api_key = os.getenv("OPENAI_API_KEY", "dummy-key-for-local")
openai_api_base = os.getenv("OPENAI_API_BASE")
openai_model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")

PROMPT = """
You are an expert Security Operations Center (SOC) Analyst. 
You are analyzing a security alert triggered by a Deep Packet Inspection (DPI) & SIEM system.
Analyze the following alert details and provide a response in exactly the following JSON format:

{{
  "explanation": "A plain english explanation of what the attack is, tailored for a junior analyst.",
  "reason": "Why the system likely flagged this (source IPs, severity, packets).",
  "mitre_context": "Explain the MITRE ATT&CK tactic/technique mentioned.",
  "recommendations": ["Action 1", "Action 2", "Action 3"]
}}

Alert Details:
Title: {title}
Description: {description}
Classification: {classification}
Severity: {severity}
Source IP: {src_ip}
Destination IP: {dst_ip}
MITRE Technique: {mitre_technique}
MITRE Tactic: {mitre_tactic}

Ensure your response is valid JSON and nothing else.
"""

class SecurityAssistant:
    def __init__(self):
        kwargs = {
            "api_key": openai_api_key,
            "model": openai_model,
            "temperature": 0.2
        }
        if openai_api_base:
            kwargs["base_url"] = openai_api_base
            
        self.llm = ChatOpenAI(**kwargs)
        self.prompt = PromptTemplate(
            template=PROMPT,
            input_variables=[
                "title", "description", "classification", "severity", 
                "src_ip", "dst_ip", "mitre_technique", "mitre_tactic"
            ]
        )
        self.chain = self.prompt | self.llm | StrOutputParser()

    def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes raw alert data and returns an AI-generated analysis.
        """
        try:
            # Provide defaults for missing fields
            inputs = {
                "title": alert_data.get("title", "Unknown Alert"),
                "description": alert_data.get("description", "No description provided"),
                "classification": alert_data.get("classification", "Unclassified"),
                "severity": alert_data.get("severity", "Unknown"),
                "src_ip": alert_data.get("src_ip", "Unknown"),
                "dst_ip": alert_data.get("dst_ip", "Unknown"),
                "mitre_technique": alert_data.get("mitre_technique", "N/A"),
                "mitre_tactic": alert_data.get("mitre_tactic", "N/A"),
            }
            
            result_str = self.chain.invoke(inputs)
            
            # Clean up potential markdown formatting wrapping the JSON
            if result_str.startswith("```json"):
                result_str = result_str.replace("```json", "", 1)
            if result_str.endswith("```"):
                result_str = result_str[:-3]
                
            return json.loads(result_str.strip())
            
        except Exception as e:
            print(f"[SecurityAssistant] Error analyzing alert: {e}")
            return {
                "explanation": "The AI Assistant encountered an error while analyzing this alert.",
                "reason": str(e),
                "mitre_context": "N/A",
                "recommendations": ["Check backend logs", "Verify OPENAI_API_KEY"]
            }

# Singleton instance
security_assistant = SecurityAssistant()
