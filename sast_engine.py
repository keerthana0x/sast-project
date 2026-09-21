import ast
import os
import json
import urllib.request
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# 1. AST Rule-Based Static Scanner
class ASTVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id == 'eval':
            self.findings.append({
                'flaw_type': 'Insecure Execution (eval)',
                'line': node.lineno,
                'code_snippet': 'eval(...)'
            })
        
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['md5', 'sha1']:
                self.findings.append({
                    'flaw_type': 'Weak Cryptographic Hash',
                    'line': node.lineno,
                    'code_snippet': f'hashlib.{node.func.attr}(...)'
                })
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(key in var_name for key in ['password', 'secret', 'api_key', 'token']):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.findings.append({
                            'flaw_type': 'Hardcoded Secret / Credential',
                            'line': node.lineno,
                            'code_snippet': f"{target.id} = '***'"
                        })
        self.generic_visit(node)


def run_ast_scanner(file_path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(file_path):
        return []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
        tree = ast.parse(code)
        visitor = ASTVisitor()
        visitor.visit(tree)
        return visitor.findings
    except Exception as e:
        return [{'flaw_type': f'Parsing Error: {str(e)}', 'line': 0, 'code_snippet': ''}]


def scan_directory_recursively(directory_path: str) -> List[Dict[str, Any]]:
    results = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.py') and not file.startswith('_temp'):
                full_path = os.path.join(root, file)
                findings = run_ast_scanner(full_path)
                if findings:
                    results.append({
                        'file': full_path,
                        'findings': findings
                    })
    return results


# 2. Gemini GenAI Verification (Handles SDK + Direct REST API Fallback)
class AIVerificationResult(BaseModel):
    is_vulnerability: bool = Field(description="True if flagged issue is a real vulnerability, False if false positive")
    explanation: str = Field(description="Detailed technical reasoning for the determination")
    remediated_code: str = Field(description="Secure, refactored version of the Python code snippet")


def verify_flaw_with_ai(flaw_type: str, snippet: str, line_no: int) -> Optional[AIVerificationResult]:
    api_key = os.getenv("GEMINI_API_KEY")
    
    try:
        import streamlit as st
        if not api_key and hasattr(st, "secrets") and "GEMINI_API_KEY" in st.secrets:
            api_key = st.secrets["GEMINI_API_KEY"]
    except Exception:
        pass

    if not api_key:
        return AIVerificationResult(
            is_vulnerability=True,
            explanation="Gemini API Key missing in Streamlit Secrets.",
            remediated_code="# Configure GEMINI_API_KEY in Streamlit Secrets to view AI fixes."
        )

    prompt_text = f"""You are an expert SAST security auditor.
Analyze this Python security issue:
Flaw Type: {flaw_type}
Line Number: {line_no}
Code Snippet:
{snippet}

Provide a JSON object response with exactly these keys:
"is_vulnerability": true or false,
"explanation": "detailed reasoning",
"remediated_code": "secure refactored python code"
"""

    # Method 1: Try official google-genai SDK
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt_text,
            config={
                'response_mime_type': 'application/json',
                'response_schema': AIVerificationResult,
            }
        )
        return AIVerificationResult.model_validate_json(response.text)
    except Exception:
        pass

    # Method 2: Direct REST API call (Supports AQ.* and non-standard key formats)
    for model_name in ['gemini-2.5-flash', 'gemini-1.5-flash']:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt_text}]}],
                "generationConfig": {"response_mime_type": "application/json"}
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            
            with urllib.request.urlopen(req, timeout=15) as resp:
                result_json = json.loads(resp.read().decode("utf-8"))
                text_content = result_json["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text_content)
                return AIVerificationResult(
                    is_vulnerability=parsed.get("is_vulnerability", True),
                    explanation=parsed.get("explanation", "Verified via Direct REST API."),
                    remediated_code=parsed.get("remediated_code", "# Code fix generated successfully.")
                )
        except Exception as err:
            last_err = str(err)
            continue

    return AIVerificationResult(
        is_vulnerability=True,
        explanation=f"AI verification error: {last_err}. Check your API key in Streamlit secrets.",
        remediated_code="# Error generating AI fix."
    )
