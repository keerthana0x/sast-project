import ast
import os
import json
import re
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


# 2. Gemini GenAI Verification & Remediation
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
            explanation="GEMINI_API_KEY is not set in Streamlit Secrets.",
            remediated_code="# Add GEMINI_API_KEY to Streamlit Secrets."
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

Respond STRICTLY with a valid JSON object using key names "is_vulnerability", "explanation", and "remediated_code".
"""

    working_models = ['gemini-flash-latest', 'gemini-2.0-flash', 'gemini-1.5-flash']
    last_error = ""

    # Method 1: Official google-genai SDK
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        for m in working_models:
            try:
                res = client.models.generate_content(
                    model=m,
                    contents=prompt_text,
                    config={'response_mime_type': 'application/json'}
                )
                parsed = json.loads(res.text)
                return AIVerificationResult(
                    is_vulnerability=parsed.get("is_vulnerability", True),
                    explanation=parsed.get("explanation", "Verified via Gemini SDK."),
                    remediated_code=parsed.get("remediated_code", "# Secure code generated.")
                )
            except Exception as sdk_ex:
                last_error = str(sdk_ex)
                continue
    except Exception:
        pass

    # Method 2: REST Fallback
    for model_name in working_models:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt_text}]}],
                "generationConfig": {"responseMimeType": "application/json"}
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            
            with urllib.request.urlopen(req, timeout=12) as response:
                res_json = json.loads(response.read().decode("utf-8"))
                text = res_json["candidates"][0]["content"]["parts"][0]["text"]
                
                json_match = re.search(r'\{.*\}', text, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group(0))
                else:
                    parsed = json.loads(text)

                return AIVerificationResult(
                    is_vulnerability=parsed.get("is_vulnerability", True),
                    explanation=parsed.get("explanation", "Verified successfully via Gemini API."),
                    remediated_code=parsed.get("remediated_code", "# Secure refactored code.")
                )
        except urllib.error.HTTPError as h_err:
            try:
                err_body = h_err.read().decode("utf-8")
                last_error = f"{model_name} [HTTP {h_err.code}]: {err_body}"
            except Exception:
                last_error = f"{model_name} [HTTP {h_err.code}]"
        except Exception as gen_err:
            last_error = f"{model_name}: {str(gen_err)}"

    return AIVerificationResult(
        is_vulnerability=True,
        explanation=f"Gemini Verification Failure: {last_error}",
        remediated_code="# Error generating AI fix."
    )
