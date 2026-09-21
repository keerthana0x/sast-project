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


# 2. Gemini GenAI Verification
class AIVerificationResult(BaseModel):
    is_vulnerability: bool = Field(description="True if flagged issue is a real vulnerability")
    explanation: str = Field(description="Detailed technical reasoning")
    remediated_code: str = Field(description="Secure refactored Python code")


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
            explanation="GEMINI_API_KEY is not configured in Streamlit Secrets.",
            remediated_code="# Please add GEMINI_API_KEY in Streamlit Secrets."
        )

    prompt_text = f"""
You are an expert static application security testing (SAST) auditor.
An AST engine flagged a potential security flaw in Python code:

Flaw Type: {flaw_type}
Line Number: {line_no}
Code Snippet:
{snippet}

Perform security verification:
1. Determine if this is a genuine vulnerability or a false positive.
2. Provide a technical explanation.
3. Provide secure, production-ready remediated Python code to fix it.

Respond strictly in valid JSON format with keys "is_vulnerability", "explanation", and "remediated_code".
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
    except Exception as sdk_err:
        pass

    # Method 2: Direct REST Call using v1beta endpoint
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
                    explanation=parsed.get("explanation", "Verified via Gemini API."),
                    remediated_code=parsed.get("remediated_code", "# Secure code generated.")
                )
        except Exception as err:
            last_err = str(err)
            continue

    return AIVerificationResult(
        is_vulnerability=True,
        explanation=f"Gemini API Error: {last_err}. Verify API key configuration.",
        remediated_code="# Error generating AI code fix."
    )
