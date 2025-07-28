from fastmcp import FastMCP
import os
import json
import re
import shutil
import ast
import yaml
import faiss
from sentence_transformers import SentenceTransformer
from google import genai
from dotenv import load_dotenv
from typing import List, Dict, Any, NamedTuple
from dataclasses import dataclass
from pathlib import Path

# Load environment variables
load_dotenv()

# --- Begin inlined dependencies ---

@dataclass
class Risk:
    """Represents a security risk found in code"""
    file_path: str
    line_number: int
    risk_type: str
    severity: str  # 'critical', 'medium', 'low'
    message: str
    suggestion: str
    source: str  # 'static' or 'claude'

class StaticRiskDetector(ast.NodeVisitor):
    """AST visitor that detects static security patterns"""
    
    # Risk patterns organized by severity
    CRITICAL_CALLS = {
        # Code execution risks
        'eval': 'Avoid eval: use ast.literal_eval or safe parsing',
        'exec': 'Avoid exec: use function dispatch or sandboxing',
        'compile': 'Avoid compile with user input: validate code source',
        # System operation risks
        'subprocess.call': 'Validate shell commands and avoid shell=True',
        'os.system': 'Use subprocess with argument lists instead',
        'os.remove': 'Validate file paths to prevent directory traversal',
        'shutil.rmtree': 'Validate paths and use absolute paths only'
    }
    
    MEDIUM_RISK_PATTERNS = {
        'bind_tools': 'Validate tools before binding to LLM',
        'tools_by_name': 'Sanitize tool names from user input',
        'open': 'Sanitize file paths and restrict destinations'
    }
    
    LOW_RISK_PATTERNS = {
        'requests.get': 'Use HTTPS and validate URLs',
        'urllib.request': 'Validate URLs and use secure protocols'
    }
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.risks: List[Risk] = []
    
    def visit_Call(self, node: ast.Call) -> None:
        """Detect risky function calls"""
        line_no = getattr(node, 'lineno', 0)
        
        # Check function name patterns
        func_name = self._get_function_name(node)
        if func_name:
            self._check_risk_patterns(func_name, line_no)
        
        self.generic_visit(node)
    
    def _get_function_name(self, node: ast.Call) -> str:
        """Extract function name from call node"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Handle module.function or obj.method calls
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return ""
    
    def _check_risk_patterns(self, func_name: str, line_no: int) -> None:
        """Check function name against risk patterns"""
        # Critical risks
        if func_name in self.CRITICAL_CALLS:
            self.risks.append(Risk(
                file_path=self.file_path,
                line_number=line_no,
                risk_type='critical_security',
                severity='critical',
                message=f'🚨 Critical: {func_name}() detected',
                suggestion=self.CRITICAL_CALLS[func_name],
                source='static'
            ))
        
        # Medium risks (AI/LangGraph specific and file operations)
        elif any(pattern in func_name for pattern in self.MEDIUM_RISK_PATTERNS):
            pattern = next(p for p in self.MEDIUM_RISK_PATTERNS if p in func_name)
            self.risks.append(Risk(
                file_path=self.file_path,
                line_number=line_no,
                risk_type='medium_security',
                severity='medium',
                message=f'⚠️ Medium risk: {pattern} usage detected',
                suggestion=self.MEDIUM_RISK_PATTERNS[pattern],
                source='static'
            ))
        
        # Low risks (network operations)
        elif any(pattern in func_name for pattern in self.LOW_RISK_PATTERNS):
            pattern = next(p for p in self.LOW_RISK_PATTERNS if p in func_name)
            self.risks.append(Risk(
                file_path=self.file_path,
                line_number=line_no,
                risk_type='low_security',
                severity='low',
                message=f'ℹ️ Low risk: {pattern} usage detected',
                suggestion=self.LOW_RISK_PATTERNS[pattern],
                source='static'
            ))

def scan_codebase_for_patterns(root_dir: str) -> List[Risk]:
    """Scan a codebase for static security patterns"""
    all_risks = []
    
    # Walk through Python files
    for file_path in Path(root_dir).rglob("*.py"):
        try:
            detector = StaticRiskDetector(str(file_path))
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
            detector.visit(tree)
            all_risks.extend(detector.risks)
        except Exception as e:
            print(f"⚠️ Failed to analyze {file_path}: {e}")
    
    return all_risks

def parse_claude_findings(claude_response: dict) -> List[Risk]:
    """Parse Claude's security findings into Risk objects"""
    risks = []
    
    # Parse constraints
    for constraint in claude_response.get("constraints", []):
        risks.append(Risk(
            file_path="claude_analysis",
            line_number=0,
            risk_type='constraint',
            severity=constraint.get("severity", "medium"),
            message=f"📋 {constraint.get('description', 'No description')}",
            suggestion="Review and implement suggested security measures",
            source='claude'
        ))
    
    # Parse risks
    for risk in claude_response.get("risks", []):
        risks.append(Risk(
            file_path="claude_analysis",
            line_number=0,
            risk_type='risk',
            severity=risk.get("severity", "medium"),
            message=f"⚠️ {risk.get('description', 'No description')}",
            suggestion=risk.get("impact", "Review security implications"),
            source='claude'
        ))
    
    return risks

def merge_risk_findings(static_risks: List[Risk], claude_risks: List[Risk]) -> Dict[str, List[Risk]]:
    """Merge static and Claude risk findings by file"""
    risks_by_file = {}
    
    # Group static risks by file
    for risk in static_risks:
        if risk.file_path not in risks_by_file:
            risks_by_file[risk.file_path] = []
        risks_by_file[risk.file_path].append(risk)
    
    # Add Claude risks to a special category
    if claude_risks:
        risks_by_file["claude_analysis"] = claude_risks
    
    return risks_by_file

def apply_comments_to_files(risks_by_file: Dict[str, List[Risk]], claude_response: dict = None) -> None:
    """Apply security comments to files based on risk findings"""
    for file_path, risks in risks_by_file.items():
        if file_path == "claude_analysis":
            continue  # Skip Claude analysis file
        _annotate_file_with_risks(file_path, risks, claude_response)

def _annotate_file_with_risks(file_path: str, risks: List[Risk], claude_response: dict = None) -> None:
    """Annotate a single file with security risk comments"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Add Claude header if available
        if claude_response:
            _insert_claude_header(lines, claude_response)
        
        # Sort risks by line number (descending) to maintain line numbers
        sorted_risks = sorted(risks, key=lambda r: r.line_number, reverse=True)
        
        # Insert risk comments
        for risk in sorted_risks:
            if risk.line_number > 0 and risk.line_number <= len(lines):
                _insert_risk_comment(lines, risk)
        
        # Write back to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        print(f"✅ Annotated {len(risks)} risks in {os.path.basename(file_path)}")
        
    except Exception as e:
        print(f"❌ Failed to annotate {file_path}: {e}")

def _insert_risk_comment(lines: List[str], risk: Risk) -> None:
    """Insert a risk comment above the specified line"""
    line_idx = risk.line_number - 1
    if line_idx >= 0 and line_idx < len(lines):
        # Get indentation from the target line
        target_line = lines[line_idx]
        indent = len(target_line) - len(target_line.lstrip())
        
        # Create comment with proper indentation
        comment = " " * indent + f"# {risk.message}\n"
        suggestion = " " * indent + f"# 💡 {risk.suggestion}\n"
        
        # Insert comments before the target line
        lines.insert(line_idx, suggestion)
        lines.insert(line_idx, comment)

def _insert_claude_header(lines: List[str], claude_response: dict) -> None:
    """Insert Claude analysis header at the top of the file"""
    header = [
        "# 🤖 AI Security Analysis Summary\n",
        "# Generated by AutoHardener with Claude analysis\n",
        "#\n"
    ]
    
    # Add key security improvements from hardened_code
    hardened_code = claude_response.get("hardened_code", [])
    if hardened_code:
        header.append("# Key security improvements:\n")
        for i, code in enumerate(hardened_code[:3], 1):  # Limit to first 3
            if code.startswith("#"):
                header.append(f"# {i}. {code[1:].strip()}\n")
            else:
                header.append(f"# {i}. {code}\n")
        header.append("#\n")
    
    # Insert header at the beginning
    lines[0:0] = header

def analyze_and_comment_codebase(root_dir: str, claude_response: dict = None) -> None:
    """Perform comprehensive security analysis and annotation"""
    print(f"🔍 Starting security analysis of: {root_dir}")
    
    # Phase 1: Static pattern detection
    print("📊 Phase 1: Static pattern detection...")
    static_risks = scan_codebase_for_patterns(root_dir)
    
    # Count risks by severity
    critical_count = sum(1 for r in static_risks if r.severity == 'critical')
    medium_count = sum(1 for r in static_risks if r.severity == 'medium')
    low_count = sum(1 for r in static_risks if r.severity == 'low')
    
    print(f"   Found {len(static_risks)} static security patterns:")
    print(f"     🚨 Critical: {critical_count}")
    print(f"     ⚠️ Medium: {medium_count}")
    print(f"     ℹ️ Low: {low_count}")
    
    # Phase 2: Integrate Claude findings
    print("🤖 Phase 2: Integrating Claude findings...")
    claude_risks = []
    if claude_response:
        claude_risks = parse_claude_findings(claude_response)
        claude_critical = sum(1 for r in claude_risks if r.severity == 'critical')
        claude_medium = sum(1 for r in claude_risks if r.severity == 'medium')
        claude_low = sum(1 for r in claude_risks if r.severity == 'low')
        
        print(f"   Claude identified {len(claude_risks)} additional risks:")
        print(f"     🚨 Critical: {claude_critical}")
        print(f"     ⚠️ Medium: {claude_medium}")
        print(f"     ℹ️ Low: {claude_low}")
    
    # Phase 3: Apply annotations
    print("✏️ Phase 3: Applying security comments...")
    risks_by_file = merge_risk_findings(static_risks, claude_risks)
    files_to_annotate = [f for f in risks_by_file.keys() if f != "claude_analysis"]
    print(f"   {len(files_to_annotate)} files need security annotations")
    
    apply_comments_to_files(risks_by_file, claude_response)
    
    # Summary
    total_risks = len(static_risks) + len(claude_risks)
    total_critical = critical_count + sum(1 for r in claude_risks if r.severity == 'critical')
    total_medium = medium_count + sum(1 for r in claude_risks if r.severity == 'medium')
    total_low = low_count + sum(1 for r in claude_risks if r.severity == 'low')
    
    print(f"\n📋 Security Analysis Summary:")
    print(f"   Total risks identified: {total_risks}")
    print(f"   🚨 Critical: {total_critical}")
    print(f"   ⚠️ Medium: {total_medium}")
    print(f"   ℹ️ Low: {total_low}")
    print("✅ Security analysis complete!")

def repair_json(text: str) -> str:
    """Basic JSON repair for common Claude output issues"""
    
    # First, try to extract JSON from code fences with proper bracket matching
    lines = text.split('\n')
    json_lines = []
    inside_json = False
    brace_count = 0
    
    for line in lines:
        # Start collecting when we hit ```json or find opening brace
        if '```json' in line or (not inside_json and '{' in line):
            inside_json = True
            # Don't include the ```json line itself
            if not line.strip().startswith('```'):
                json_lines.append(line)
                brace_count += line.count('{') - line.count('}')
        elif inside_json:
            # Stop when we hit ``` or when braces are balanced
            if line.strip() == '```':
                break
            json_lines.append(line)
            brace_count += line.count('{') - line.count('}')
            
            # Stop when we have a complete JSON object
            if brace_count == 0 and json_lines:
                break
    
    if json_lines:
        extracted = '\n'.join(json_lines).strip()
        
        # Fix common Claude JSON issues
        return fix_json_syntax(extracted)
    
    # Fallback: look for JSON object boundaries
    start = text.find('{')
    end = text.rfind('}')
    
    if start == -1 or end == -1:
        return text
    
    extracted = text[start:end+1].strip()
    return fix_json_syntax(extracted)

def fix_json_syntax(json_text: str) -> str:
    """Fix common JSON syntax issues from Claude's output"""
    
    # Claude sometimes puts actual Python code with triple quotes in JSON strings
    # We need to escape these properly for JSON
    
    # First, handle the case where Claude puts unescaped triple quotes
    # Replace """...""" with properly escaped JSON string
    def replace_triple_quotes(match):
        content = match.group(1)
        # Escape quotes and newlines for JSON
        escaped = content.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
        return f'"{escaped}"'
    
    # Handle unescaped triple quotes
    json_text = re.sub(r'"""(.*?)"""', replace_triple_quotes, json_text, flags=re.DOTALL)
    
    # Handle the case where Claude puts template strings that break JSON structure
    # Fix lines that contain standalone triple quotes (like the PROMPT_TEMPLATE case)
    lines = json_text.split('\n')
    fixed_lines = []
    
    for line in lines:
        # If a line contains just triple quotes, it's likely breaking the JSON structure
        stripped = line.strip()
        if stripped == '"\"\"\"",' or stripped == '"\"\"\""':
            # Skip these problematic lines - they're usually part of a malformed multi-line string
            continue
        elif stripped.startswith('"PROMPT_TEMPLATE = ""') or 'PROMPT_TEMPLATE' in stripped:
            # Handle the specific PROMPT_TEMPLATE case - convert to a single escaped string
            # This is a common pattern Claude uses that breaks JSON
            continue
        else:
            fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def parse_guardrail_response(raw_output: str) -> dict:
    """Parse Claude's response with robust error handling and schema validation"""
    
    if not isinstance(raw_output, str):
        raise ValueError("Expected string response from Claude")
    
    # Try direct parsing first
    try:
        parsed = json.loads(raw_output)
    except json.JSONDecodeError:
        # Try to repair and parse
        try:
            repaired = repair_json(raw_output)
            parsed = json.loads(repaired)
        except json.JSONDecodeError:
            # Final fallback: extract JSON with regex
            match = re.search(r'\{[\s\S]*\}', raw_output)
            if match:
                try:
                    parsed = json.loads(match.group())
                except json.JSONDecodeError:
                    raise ValueError("Could not parse JSON from Claude's response")
            else:
                raise ValueError("No JSON object found in Claude's response")
    
    return validate_schema(parsed)

def validate_schema(parsed: dict) -> dict:
    """Validate and ensure all required fields are present"""
    
    # Define required fields with defaults
    required_fields = {
        "constraints": [],
        "risks": [],
        "hardened_code": []
    }
    
    # Ensure all required fields exist
    for field, default in required_fields.items():
        if field not in parsed:
            print(f"⚠️  Missing field '{field}', using default: {default}")
            parsed[field] = default
    
    return parsed

def get_guardrails(agent_data, tool_data, routing_logic, retrieved_context=""):
    """Get security guardrails from Claude using Google Gemini API"""
    system_prompt = "You are a security auditor for AI agents. Identify vulnerabilities and suggest safety guardrails."

    user_prompt = f"""
You are a security auditor for AI agents. 
You will scan through the given repository that is passed to you as the codebase(routing logic) and some data derived from the repository. 
You are to provide specifically security recommendations for the agent's codebase. You are not to provide any other recommendations.
You are to operate in the two phases that follow:
Phase 1 (The routing_logic comprehension phase):
    The routing logic that you have been passed is the codebase that you are scanning. In this initial phase, you are to understand the codebase. You should 
    seek to understand: 
    - What the overall purpose of the agentic system is.
    - How the agentic system is structured.
    - What, if any, user input is used in the codebase.
    - How the agentic system is designed to handle security.
    - How the agentic system is designed to handle privacy.
    - How the agentic system is designed to handle compliance.
    - How the agentic system manages data.
    
Phase 2 (The security recommendations phase):
    Given the agent's metadata and routing logic, identify vulnerabilities such as:
    - prompt injection risks (no/little prompting, overly broad prompts, agents with a lot of freeom/power)
    - tool misuse
    - sensitive code execution without human validation
    - unsafe external API, MCP server, or other external service tool use

    Then write Python code that mitigates these risks.
    Each fix should include a **clear comment** explaining what it does.
    The biggest priority is to make sure the code is valid, complete, and fits within the existing codebase.
    Disfunctional code is worth less than minimal code that gives users a basic understanding of how to harden their code.

    Here is your JSON response format:

```json
{{
  "constraints": [
    {{
      "description": "Brief description of constraint",
      "severity": "critical|medium|low"
    }}
  ],
  "risks": [
    {{
      "description": "Brief description of risk",
      "severity": "critical|medium|low",
      "impact": "Brief description of potential impact"
    }}
  ],
  "hardened_code": [
    "# Comment explaining this code",
    "def secure_function():",
    "    return validated_input"
  ]
}}
```

    SEVERITY GUIDELINES:
    - critical: Immediate security threat (code execution, data breach, system compromise)
    - medium: Significant security concern (privilege escalation, data exposure, service disruption)  
    - low: Minor security issue (information disclosure, weak validation, configuration concerns)

IMPORTANT: 
- Respond with ONLY the JSON inside triple backticks as shown above
- Assign appropriate severity levels to ALL constraints and risks
- Keep descriptions brief (under 50 words each)
- Keep code examples concise but functional
- Ensure the JSON is complete and valid
- Do not add any explanatory text before or after the JSON
- When assessing severity levels, only use the following severity levels: critical, medium, low.

    Agent card:
    {agent_data}
    Tool schema:
    {tool_data}

    Routing logic:
    {routing_logic}

    Context:
    {retrieved_context}
    """
    
    # Get API key from environment
    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError("GOOGLE_API_KEY environment variable not set")
    
    client = genai.Client(api_key=api_key)
    # Send request with function declarations
    response = client.models.generate_content(
        model="gemini-2.5-pro",
        contents=[user_prompt],
    )    
    # Use robust parsing instead of returning raw text
    try:
        return parse_guardrail_response(response.text)
    except ValueError as e:
        print(f"❌ Failed to parse Claude's response: {e}")
        return None

def extract_metadata_from_file(filepath):
    """Extract metadata from a Python file"""
    with open(filepath, "r", encoding="utf-8") as f:
        code = f.read()
    
    # Basic metadata extraction
    agent_card = {
        "name": os.path.basename(filepath).replace('.py', ''),
        "description": f"AI agent from {filepath}",
        "file_path": filepath
    }
    
    tool_schema = {
        "tools": "Various tools and functions defined in the agent"
    }
    
    routing_logic = code  # send the whole agent logic to Claude
    return agent_card, tool_schema, routing_logic

def inject_guardrails_yaml(yaml_path, guardrails):
    """Inject guardrails into a YAML file"""
    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        data = {}
    
    data.setdefault("security", {})
    data["security"]["constraints"] = guardrails.get("constraints", [])
    data["security"]["risks"] = guardrails.get("risks", [])
    data["security"]["suggested_guardrails"] = guardrails.get("hardened_code", [])
    
    with open(yaml_path, 'w') as f:
        yaml.safe_dump(data, f, default_flow_style=False)
    
    print(f"✅ Guardrails injected into {yaml_path}")

def load_threats(filepath=None):
    """Load threat data from markdown file"""
    if filepath is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(base_dir, "threat_list/owasp_top_10.md")
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        entries = content.split("\n---\n")
        threats = []
        for entry in entries:
            lines = entry.strip().split("\n")
            if lines:
                title = lines[0].replace("##", "").strip()
                desc = "\n".join(lines[1:]).strip()
                threats.append({"title": title, "text": desc})
        return threats
    except FileNotFoundError:
        print(f"⚠️ Threat file not found: {filepath}")
        return []

def build_index(threats, model):
    """Build FAISS index from threats"""
    if not threats:
        return None, None
    
    texts = [t["title"] + "\n" + t["text"] for t in threats]
    vectors = model.encode(texts)
    index = faiss.IndexFlatL2(vectors[0].shape[0])
    index.add(vectors)
    return index, vectors

def retrieve_context(query, k=3):
    """Retrieve relevant threat context"""
    try:
        model = SentenceTransformer("all-MiniLM-L6-v2")
        threats = load_threats()
        if not threats:
            return ""
        
        index, _ = build_index(threats, model)
        if index is None:
            return ""
        
        query_vec = model.encode([query])
        D, I = index.search(query_vec, k)
        results = []
        for idx in I[0]:
            if idx < len(threats):
                results.append(threats[idx]["text"])
        return "\n\n".join(results)
    except Exception as e:
        print(f"⚠️ Context retrieval failed: {e}")
        return ""

# --- End inlined dependencies ---

mcp = FastMCP(name="AutohardenerServer")

@mcp.tool
def autoharden_agent(agent_path: str) -> dict:
    """Analyze and harden an AI agent with security guardrails"""
    try:
        print(f"🔍 Analyzing: {agent_path}")
        
        # Check if file exists
        if not os.path.exists(agent_path):
            return {
                "error": f"File not found: {agent_path}",
                "success": False
            }
        
        # Determine paths
        file_path = agent_path
        root_dir = os.path.dirname(os.path.abspath(file_path))
        yaml_path = file_path.replace(".py", "_card.yaml")
        
        # Retrieve security context
        retrieved_context = retrieve_context("prompt injection, tool misuse, agent execution")
        
        # Extract metadata
        agent_card, tool_schema, routing_logic = extract_metadata_from_file(file_path)
        agent_card_str = json.dumps(agent_card, indent=2)
        tool_schema_str = json.dumps(tool_schema, indent=2)
        
        # Get guardrails from Claude
        print("🧠 Generating guardrail suggestions...")
        parsed = get_guardrails(agent_card_str, tool_schema_str, routing_logic, retrieved_context)
        
        if not parsed:
            return {
                "error": "Failed to generate guardrails",
                "success": False
            }
        
        # Apply security analysis and annotations
        print("🔒 Applying security analysis...")
        analyze_and_comment_codebase(root_dir, parsed)
        
        # Inject guardrails into YAML if requested
        if os.path.exists(yaml_path):
            inject_guardrails_yaml(yaml_path, parsed)
        
        # Format results for display
        constraints = parsed.get("constraints", [])
        risks = parsed.get("risks", [])
        
        result = {
            "success": True,
            "file_path": file_path,
            "yaml_path": yaml_path,
            "yaml_exists": os.path.exists(yaml_path),
            "constraints_count": len(constraints),
            "risks_count": len(risks),
            "constraints": constraints,
            "risks": risks,
            "hardened_code": parsed.get("hardened_code", []),
            "message": f"✅ Successfully analyzed and hardened {os.path.basename(file_path)}"
        }
        
        return result
        
    except Exception as e:
        return {
            "error": str(e),
            "success": False,
            "file_path": agent_path
        }

@mcp.tool
def ping_pong(random_string: str = "test") -> dict:
    """A dummy tool that returns pong."""
    return {"response": "pong", "input": random_string}

if __name__ == "__main__":
    mcp.run() 