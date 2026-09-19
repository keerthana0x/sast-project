import os
import ast
import time
import sys
from dataclasses import dataclass
from typing import List, Optional
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

# ----------------------------------------------------
# STAGE 1: LOCAL AST PARSER
# ----------------------------------------------------
@dataclass
class CandidateFlaw:
    filename: str
    line_number: int
    vulnerability_type: str
    code_snippet: str

class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, source_lines: List[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.candidates: List[CandidateFlaw] = []

    def visit_Call(self, node):
        # 1. Dangerous dynamic code execution
        if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:
            self._add_candidate(node, "Code Execution Risk")
            
        # 2. Unescaped SQL string execution
        elif isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                self._add_candidate(node, "SQL Injection Risk")
                
        # 3. Dangerous OS command execution
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ['system', 'popen']:
            self._add_candidate(node, "OS Command Injection Risk")
            
        self.generic_visit(node)

    def _add_candidate(self, node: ast.AST, vuln_type: str):
        line_no = getattr(node, 'lineno', 1)
        start = max(0, line_no - 3)
        end = min(len(self.source_lines), line_no + 2)
        snippet = "".join(self.source_lines[start:end])
        self.candidates.append(
            CandidateFlaw(self.filename, line_no, vuln_type, snippet)
        )

def scan_file_locally(filepath: str) -> List[CandidateFlaw]:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        lines = content.splitlines(keepends=True)
        tree = ast.parse(content, filename=filepath)
        visitor = SecurityASTVisitor(filepath, lines)
        visitor.visit(tree)
        return visitor.candidates
    except (SyntaxError, UnicodeDecodeError, PermissionError):
        # Gracefully skip unparseable files, binary files, or bad syntax
        return []

def scan_directory_recursively(target_dir: str) -> List[CandidateFlaw]:
    all_candidates: List[CandidateFlaw] = []
    ignored_dirs = {'.git', 'venv', '.venv', '__pycache__', 'node_modules', '.idea'}

    print(f"[*] Scanning directory: '{os.path.abspath(target_dir)}'")
    
    for root, dirs, files in os.walk(target_dir):
        # Prune ignored directories in-place
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                file_candidates = scan_file_locally(filepath)
                if file_candidates:
                    print(f"    [+] Found {len(file_candidates)} candidate(s) in {filepath}")
                    all_candidates.extend(file_candidates)
                    
    return all_candidates

# ----------------------------------------------------
# STAGE 2: AI VERIFICATION JUDGE (Gemini + Pydantic)
# ----------------------------------------------------
class SecurityAnalysis(BaseModel):
    is_real_vulnerability: bool = Field(description="True if genuine security threat, False if false alarm")
    severity: str = Field(description="High, Medium, Low, or None")
    explanation: str = Field(description="Brief explanation of why it is or isn't a threat")
    fixed_code: str = Field(description="Corrected secure code snippet")

def verify_flaw_with_ai(flaw: CandidateFlaw) -> Optional[SecurityAnalysis]:
    if "GEMINI_API_KEY" not in os.environ:
        print("[!] Error: GEMINI_API_KEY missing from environment variables.")
        return None

    client = genai.Client()
    prompt = f"""
    You are an expert Application Security Auditor.
    Analyze this Python code snippet from file '{flaw.filename}' flagged as '{flaw.vulnerability_type}'.

    Code Snippet:
    {flaw.code_snippet}

    Determine if this is a true vulnerability or a false positive. If true, supply a secure fix.
    """

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model='gemini-3.6-flash',
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=SecurityAnalysis,
                    temperature=0.1,
                ),
            )
            return response.parsed
        except Exception as e:
            if attempt < 2:
                time.sleep(2)
            else:
                print(f"      [!] API Error for {flaw.filename}:{flaw.line_number} -> {e}")
                return None

# ----------------------------------------------------
# STAGE 3: HTML REPORT GENERATOR
# ----------------------------------------------------
def generate_html_report(results: list, scanned_dir: str, output_filename="audit_report.html"):
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AI-SAST Audit Dashboard</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; margin: 30px; }}
            h1 {{ color: #1e293b; margin-bottom: 5px; }}
            .subtitle {{ color: #64748b; margin-bottom: 25px; }}
            .card {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
            .High {{ border-left: 6px solid #ef4444; }}
            .Medium {{ border-left: 6px solid #f59e0b; }}
            .Low {{ border-left: 6px solid #3b82f6; }}
            .badge {{ padding: 4px 10px; border-radius: 12px; color: white; font-weight: bold; font-size: 0.85em; background: #1e293b; float: right; }}
            pre {{ background: #1e293b; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.9em; }}
            code {{ font-family: 'Courier New', Courier, monospace; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Hybrid AI-SAST Audit Report</h1>
        <div class="subtitle">Target Directory: <code>{os.path.abspath(scanned_dir)}</code> | Total Verified Threat(s): {len(results)}</div>
    """
    
    for item in results:
        flaw = item["flaw"]
        ai = item["ai"]
        html_content += f"""
        <div class="card {ai.severity}">
            <span class="badge">{ai.severity} SEVERITY</span>
            <h2>{flaw.vulnerability_type}</h2>
            <p><strong>File:</strong> <code>{flaw.filename}</code> (Line {flaw.line_number})</p>
            <p><strong>AI Analysis:</strong> {ai.explanation}</p>
            <h3>Vulnerable Code Snippet:</h3>
            <pre><code>{flaw.code_snippet}</code></pre>
            <h3>Recommended Fix:</h3>
            <pre><code>{ai.fixed_code}</code></pre>
        </div>
        """

    html_content += "</body></html>"
    
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"\n[+] Audit Report successfully generated: {os.path.abspath(output_filename)}")

# ----------------------------------------------------
# MAIN EXECUTION PIPELINE
# ----------------------------------------------------
if __name__ == "__main__":
    # Determine directory to scan (defaults to current folder '.' or argument if passed)
    target_directory = sys.argv[1] if len(sys.argv) > 1 else "."

    print(f"\n==================================================")
    print(f"       HYBRID AI-SAST SECURITY ENGINE            ")
    print(f"==================================================\n")

    # Step 1: Local Scan
    print("[*] Step 1: Running Stage 1 Local AST Scan across codebase...")
    candidates = scan_directory_recursively(target_directory)
    print(f"    --> Found {len(candidates)} candidate security sink(s) in total.\n")

    if not candidates:
        print("[✓] No candidate vulnerabilities found in the target directory.")
        sys.exit(0)

    # Step 2: AI Verification
    verified_results = []
    print("[*] Step 2: Running Stage 2 Gemini AI Verification...")
    for flaw in candidates:
        print(f"    - Checking {flaw.filename}:{flaw.line_number} ({flaw.vulnerability_type})...")
        ai_result = verify_flaw_with_ai(flaw)
        
        if ai_result and ai_result.is_real_vulnerability:
            print(f"      [!] CONFIRMED THREAT [{ai_result.severity}]")
            verified_results.append({"flaw": flaw, "ai": ai_result})
        else:
            print("      [✓] DROPPED (False Alarm)")

    # Step 3: Report Generation
    print(f"\n[*] Step 3: Generating HTML Dashboard for {len(verified_results)} verified vulnerability(ies)...")
    generate_html_report(verified_results, target_directory)