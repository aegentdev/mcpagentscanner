# Force UTF-8 encoding for Windows compatibility - MUST BE FIRST
import sys
import os

# Set UTF-8 encoding before any other imports
if sys.platform == "win32":
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    os.environ['PYTHONUTF8'] = '1'
    
    # Force UTF-8 encoding for all operations
    import codecs
    codecs.register(lambda name: codecs.lookup('utf-8') if name == 'cp1252' else None)
    
    # Reconfigure stdout and stderr
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from fastmcp import FastMCP
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
  


def safe_print(text):
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode('ascii', 'replace').decode('ascii'))

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
    source: str  # 'static' or 'gemini'

@dataclass
class AgentContext:
    """Structured context extracted from LLM analysis to guide static analysis"""
    # Agent characteristics
    has_prompt_injection_risk: bool = False
    uses_dynamic_tool_routing: bool = False
    user_input_flows_to_llm: bool = False
    has_code_execution_capability: bool = False
    has_file_system_access: bool = False
    has_network_access: bool = False
    
    # Tool analysis
    tools: List[str] = None
    entrypoints: List[str] = None
    critical_functions: List[str] = None
    
    # Risk patterns from LLM
    llm_identified_risks: List[str] = None
    llm_constraints: List[str] = None
    
    # Context-aware severity adjustments
    severity_multipliers: Dict[str, float] = None
    
    def __post_init__(self):
        if self.tools is None:
            self.tools = []
        if self.entrypoints is None:
            self.entrypoints = []
        if self.critical_functions is None:
            self.critical_functions = []
        if self.llm_identified_risks is None:
            self.llm_identified_risks = []
        if self.llm_constraints is None:
            self.llm_constraints = []
        if self.severity_multipliers is None:
            self.severity_multipliers = {}

def build_agent_context(gemini_response: dict) -> AgentContext:
    """Extract structured context from Gemini's analysis to guide static analysis"""
    context = AgentContext()
    
    if not gemini_response:
        return context
    
    # Analyze constraints for agent characteristics
    constraints = gemini_response.get("constraints", [])
    for constraint in constraints:
        description = constraint.get("description", "").lower()
        severity = constraint.get("severity", "medium")
        
        # Detect agent characteristics from constraint descriptions
        if any(keyword in description for keyword in ["prompt injection", "user input", "untrusted input"]):
            context.has_prompt_injection_risk = True
            context.user_input_flows_to_llm = True
        
        if any(keyword in description for keyword in ["tool routing", "dynamic tool", "tool selection"]):
            context.uses_dynamic_tool_routing = True
        
        if any(keyword in description for keyword in ["code execution", "eval", "exec", "compile"]):
            context.has_code_execution_capability = True
        
        if any(keyword in description for keyword in ["file system", "file access", "file operation"]):
            context.has_file_system_access = True
        
        if any(keyword in description for keyword in ["network", "api", "http", "external"]):
            context.has_network_access = True
        
        # Store constraint for context
        context.llm_constraints.append(description)
    
    # Analyze risks for additional context
    risks = gemini_response.get("risks", [])
    for risk in risks:
        description = risk.get("description", "").lower()
        impact = risk.get("impact", "").lower()
        
        # Extract tool mentions
        tool_keywords = ["tool", "function", "api", "service", "execution"]
        for keyword in tool_keywords:
            if keyword in description or keyword in impact:
                context.tools.append(keyword)
        
        # Store risk for context
        context.llm_identified_risks.append(description)
    
    # Analyze hardened code for critical functions
    hardened_code = gemini_response.get("hardened_code", [])
    for code_line in hardened_code:
        if isinstance(code_line, str) and "def " in code_line:
            # Extract function name from hardened code
            func_match = re.search(r'def\s+(\w+)', code_line)
            if func_match:
                context.critical_functions.append(func_match.group(1))
    
    # Set severity multipliers based on context
    if context.has_prompt_injection_risk:
        context.severity_multipliers["user_input_related"] = 1.5  # Upgrade severity
    
    if context.has_code_execution_capability:
        context.severity_multipliers["code_execution"] = 2.0  # Critical upgrade
    
    if context.uses_dynamic_tool_routing:
        context.severity_multipliers["tool_routing"] = 1.8  # High upgrade
    
    if context.has_file_system_access:
        context.severity_multipliers["file_operations"] = 1.3  # Medium upgrade
    
    print(f"Built agent context:")
    print(f"   Prompt injection risk: {context.has_prompt_injection_risk}")
    print(f"   Dynamic tool routing: {context.uses_dynamic_tool_routing}")
    print(f"   Code execution capability: {context.has_code_execution_capability}")
    print(f"   File system access: {context.has_file_system_access}")
    print(f"   Network access: {context.has_network_access}")
    print(f"   Severity multipliers: {context.severity_multipliers}")
    
    return context

class StaticRiskDetector(ast.NodeVisitor):
    """AST visitor that detects static security patterns with LLM context awareness"""
    
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
    
    # Context-aware pattern categories
    USER_INPUT_PATTERNS = {
        'input': 'Validate and sanitize user input',
        'raw_input': 'Use input() with proper validation',
        'getpass': 'Validate password input securely'
    }
    
    TOOL_ROUTING_PATTERNS = {
        'tools_by_name': 'Sanitize tool names from user input',
        'bind_tools': 'Validate tools before binding to LLM',
        'get_tool': 'Validate tool selection dynamically',
        'execute_tool': 'Validate tool execution parameters'
    }
    
    def __init__(self, file_path: str, context: AgentContext = None):
        self.file_path = file_path
        self.context = context or AgentContext()
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
        """Check function name against risk patterns with context-aware severity adjustment"""
        
        # Determine base severity and pattern
        base_severity = 'low'
        pattern = None
        suggestion = None
        
        # Check critical patterns first
        if func_name in self.CRITICAL_CALLS:
            base_severity = 'critical'
            pattern = func_name
            suggestion = self.CRITICAL_CALLS[func_name]
        
        # Check medium patterns
        elif any(p in func_name for p in self.MEDIUM_RISK_PATTERNS):
            pattern = next(p for p in self.MEDIUM_RISK_PATTERNS if p in func_name)
            base_severity = 'medium'
            suggestion = self.MEDIUM_RISK_PATTERNS[pattern]
        
        # Check low patterns
        elif any(p in func_name for p in self.LOW_RISK_PATTERNS):
            pattern = next(p for p in self.LOW_RISK_PATTERNS if p in func_name)
            base_severity = 'low'
            suggestion = self.LOW_RISK_PATTERNS[pattern]
        
        # Check context-specific patterns
        elif self.context.has_prompt_injection_risk and any(p in func_name for p in self.USER_INPUT_PATTERNS):
            pattern = next(p for p in self.USER_INPUT_PATTERNS if p in func_name)
            base_severity = 'medium'  # Upgrade from low to medium for user input
            suggestion = self.USER_INPUT_PATTERNS[pattern]
        
        elif self.context.uses_dynamic_tool_routing and any(p in func_name for p in self.TOOL_ROUTING_PATTERNS):
            pattern = next(p for p in self.TOOL_ROUTING_PATTERNS if p in func_name)
            base_severity = 'critical'  # Upgrade to critical for dynamic tool routing
            suggestion = self.TOOL_ROUTING_PATTERNS[pattern]
        
        # Apply context-aware severity adjustments
        final_severity = self._adjust_severity_with_context(base_severity, func_name, pattern)
        
        # Create risk if pattern was found
        if pattern and suggestion:
            risk_type = f"{final_severity}_security"
            if final_severity == 'critical':
                message = f'Critical: {pattern}() detected'
            elif final_severity == 'medium':
                message = f'Medium risk: {pattern} usage detected'
            else:
                message = f'Low risk: {pattern} usage detected'
            
            # Add context information to suggestion if relevant
            enhanced_suggestion = self._enhance_suggestion_with_context(suggestion, func_name)
            
            self.risks.append(Risk(
                file_path=self.file_path,
                line_number=line_no,
                risk_type=risk_type,
                severity=final_severity,
                message=message,
                suggestion=enhanced_suggestion,
                source='static'
            ))
    
    def _adjust_severity_with_context(self, base_severity: str, func_name: str, pattern: str) -> str:
        """Adjust severity based on agent context"""
        severity_levels = ['low', 'medium', 'critical']
        current_index = severity_levels.index(base_severity)
        
        # Check for code execution capability
        if self.context.has_code_execution_capability and any(exec_func in func_name for exec_func in ['eval', 'exec', 'compile', 'subprocess']):
            multiplier = self.context.severity_multipliers.get("code_execution", 2.0)
            if multiplier >= 1.5:
                return 'critical'
        
        # Check for user input related patterns
        if self.context.has_prompt_injection_risk and any(input_func in func_name for input_func in ['input', 'raw_input', 'getpass']):
            multiplier = self.context.severity_multipliers.get("user_input_related", 1.5)
            if multiplier >= 1.5 and current_index < 2:
                return severity_levels[current_index + 1]
        
        # Check for tool routing patterns
        if self.context.uses_dynamic_tool_routing and any(tool_func in func_name for tool_func in ['tools_by_name', 'bind_tools', 'get_tool']):
            multiplier = self.context.severity_multipliers.get("tool_routing", 1.8)
            if multiplier >= 1.5 and current_index < 2:
                return severity_levels[current_index + 1]
        
        # Check for file operations
        if self.context.has_file_system_access and any(file_func in func_name for file_func in ['open', 'os.remove', 'shutil.rmtree']):
            multiplier = self.context.severity_multipliers.get("file_operations", 1.3)
            if multiplier >= 1.3 and current_index < 2:
                return severity_levels[current_index + 1]
        
        return base_severity
    
    def _enhance_suggestion_with_context(self, base_suggestion: str, func_name: str) -> str:
        """Enhance suggestion with context-specific guidance"""
        enhanced = base_suggestion
        
        # Add context-specific warnings
        if self.context.has_prompt_injection_risk and any(input_func in func_name for input_func in ['input', 'raw_input']):
                            enhanced += " (Agent has prompt injection risk - validate input thoroughly)"
        
        if self.context.uses_dynamic_tool_routing and any(tool_func in func_name for tool_func in ['tools_by_name', 'bind_tools']):
                            enhanced += " (Agent uses dynamic tool routing - implement strict tool validation)"
        
        if self.context.has_code_execution_capability and any(exec_func in func_name for exec_func in ['eval', 'exec', 'compile']):
                            enhanced += " (Agent has code execution capability - implement sandboxing)"
        
        return enhanced

def scan_codebase_for_patterns(root_dir: str, context: AgentContext = None) -> List[Risk]:
    """Scan a codebase for static security patterns with LLM context awareness"""
    all_risks = []
    
    # Walk through Python files
    for file_path in Path(root_dir).rglob("*.py"):
        try:
            detector = StaticRiskDetector(str(file_path), context)
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
            detector.visit(tree)
            all_risks.extend(detector.risks)
        except Exception as e:
            safe_print(f"[WARNING] Failed to analyze {file_path}: {e}")
    
    return all_risks

def parse_gemini_findings(gemini_response: dict) -> List[Risk]:
    """Parse Gemini's security findings into Risk objects"""
    risks = []
    
    # Parse constraints
    for constraint in gemini_response.get("constraints", []):
        risks.append(Risk(
            file_path="gemini_analysis",
            line_number=0,
            risk_type='constraint',
            severity=constraint.get("severity", "medium"),
            message=f"[CLIPBOARD] {constraint.get('description', 'No description')}",
            suggestion="Review and implement suggested security measures",
            source='gemini'
        ))
    
    # Parse risks
    for risk in gemini_response.get("risks", []):
        risks.append(Risk(
            file_path="gemini_analysis",
            line_number=0,
            risk_type='risk',
            severity=risk.get("severity", "medium"),
            message=f"[WARNING] {risk.get('description', 'No description')}",
            suggestion=risk.get("impact", "Review security implications"),
            source='gemini'
        ))
    
    return risks

def merge_risk_findings(static_risks: List[Risk], gemini_risks: List[Risk]) -> Dict[str, List[Risk]]:
    """Merge static and Gemini risk findings by file"""
    risks_by_file = {}
    
    # Group static risks by file
    for risk in static_risks:
        if risk.file_path not in risks_by_file:
            risks_by_file[risk.file_path] = []
        risks_by_file[risk.file_path].append(risk)
    
    # Add Gemini risks to a special category
    if gemini_risks:
        risks_by_file["gemini_analysis"] = gemini_risks
    
    return risks_by_file

def apply_comments_to_files(risks_by_file: Dict[str, List[Risk]], gemini_response: dict = None) -> None:
    """Apply security comments to files based on risk findings"""
    for file_path, risks in risks_by_file.items():
        if file_path == "gemini_analysis":
            continue  # Skip Gemini analysis file
        _annotate_file_with_risks(file_path, risks, gemini_response)

def _annotate_file_with_risks(file_path: str, risks: List[Risk], gemini_response: dict = None) -> None:
    """Annotate a single file with security risk comments"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Add Gemini header if available
        if gemini_response:
            _insert_gemini_header(lines, gemini_response)
        
        # Sort risks by line number (descending) to maintain line numbers
        sorted_risks = sorted(risks, key=lambda r: r.line_number, reverse=True)
        
        # Insert risk comments
        for risk in sorted_risks:
            if risk.line_number > 0 and risk.line_number <= len(lines):
                _insert_risk_comment(lines, risk)
        
        # Write back to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        safe_print(f"[CHECK] Annotated {len(risks)} risks in {os.path.basename(file_path)}")
        
    except Exception as e:
        safe_print(f"[ERROR] Failed to annotate {file_path}: {e}")

def _insert_risk_comment(lines: List[str], risk: Risk) -> None:
    """Insert a risk comment above the specified line"""
    line_idx = risk.line_number - 1
    if line_idx >= 0 and line_idx < len(lines):
        # Get indentation from the target line
        target_line = lines[line_idx]
        indent = len(target_line) - len(target_line.lstrip())
        
        # Create comment with proper indentation
        comment = " " * indent + f"# {risk.message}\n"
        suggestion = " " * indent + f"# [TIP] {risk.suggestion}\n"
        
        # Insert comments before the target line
        lines.insert(line_idx, suggestion)
        lines.insert(line_idx, comment)

def _insert_gemini_header(lines: List[str], gemini_response: dict) -> None:
    """Insert Gemini analysis header at the top of the file"""
    header = [
        "# [BOT] AI Security Analysis Summary\n",
        "# Generated by AutoHardener with Gemini analysis\n",
        "#\n"
    ]
    
    # Add key security improvements from hardened_code
    hardened_code = gemini_response.get("hardened_code", [])
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

def analyze_and_comment_codebase(root_dir: str, gemini_response: dict = None) -> None:
    """Perform comprehensive security analysis and annotation with LLM-augmented static analysis"""
    print(f"Starting hybrid security analysis of: {root_dir}")
    
    # Phase 1: LLM Context Building
    print("Phase 1: Building agent context from LLM analysis...")
    agent_context = build_agent_context(gemini_response)
    
    if agent_context.has_prompt_injection_risk or agent_context.uses_dynamic_tool_routing:
        safe_print("   [ALERT] High-risk agent detected - applying enhanced security checks")
    else:
        safe_print("   [CHECK] Standard security checks applied")
    
    # Phase 2: Context-Aware Static Pattern Detection
    print("Phase 2: Context-aware static pattern detection...")
    static_risks = scan_codebase_for_patterns(root_dir, agent_context)
    
    # Count risks by severity
    critical_count = sum(1 for r in static_risks if r.severity == 'critical')
    medium_count = sum(1 for r in static_risks if r.severity == 'medium')
    low_count = sum(1 for r in static_risks if r.severity == 'low')
    
    print(f"   Found {len(static_risks)} context-aware security patterns:")
    safe_print(f"     [ALERT] Critical: {critical_count}")
    safe_print(f"     [WARNING] Medium: {medium_count}")
    safe_print(f"     [INFO] Low: {low_count}")
    
    # Show context-specific findings
    context_enhanced_risks = [r for r in static_risks if "context" in r.suggestion.lower() or "agent" in r.suggestion.lower()]
    if context_enhanced_risks:
        safe_print(f"   [TARGET] {len(context_enhanced_risks)} risks enhanced with agent context")
    
    # Phase 3: Integrate Gemini findings
    safe_print("[BOT] Phase 3: Integrating Gemini findings...")
    gemini_risks = []
    if gemini_response:
        gemini_risks = parse_gemini_findings(gemini_response)
        gemini_critical = sum(1 for r in gemini_risks if r.severity == 'critical')
        gemini_medium = sum(1 for r in gemini_risks if r.severity == 'medium')
        gemini_low = sum(1 for r in gemini_risks if r.severity == 'low')
        
        print(f"   Gemini identified {len(gemini_risks)} additional risks:")
        safe_print(f"     [ALERT] Critical: {gemini_critical}")
        safe_print(f"     [WARNING] Medium: {gemini_medium}")
        safe_print(f"     [INFO] Low: {gemini_low}")
    
    # Phase 4: Apply annotations
    safe_print("[PENCIL] Phase 4: Applying security comments...")
    risks_by_file = merge_risk_findings(static_risks, gemini_risks)
    files_to_annotate = [f for f in risks_by_file.keys() if f != "gemini_analysis"]
    print(f"   {len(files_to_annotate)} files need security annotations")
    
    apply_comments_to_files(risks_by_file, gemini_response)
    
    # Summary with context information
    total_risks = len(static_risks) + len(gemini_risks)
    total_critical = critical_count + sum(1 for r in gemini_risks if r.severity == 'critical')
    total_medium = medium_count + sum(1 for r in gemini_risks if r.severity == 'medium')
    total_low = low_count + sum(1 for r in gemini_risks if r.severity == 'low')
    
    safe_print(f"\n[CLIPBOARD] Hybrid Security Analysis Summary:")
    safe_print(f"   Total risks identified: {total_risks}")
    safe_print(f"   [ALERT] Critical: {total_critical}")
    safe_print(f"   [WARNING] Medium: {total_medium}")
    safe_print(f"   [INFO] Low: {total_low}")
    
    # Context summary
    if agent_context.severity_multipliers:
        safe_print(f"   [TARGET] Context adjustments applied: {len(agent_context.severity_multipliers)} severity multipliers")
    
    safe_print("[CHECK] Hybrid security analysis complete!")

def analyze_hardened_code_effectiveness(original_risks: List[Risk], gemini_response: dict) -> dict:
    """Analyze how well the hardened code addresses the original risks"""
    if not gemini_response or not original_risks:
        return {"effectiveness": "unknown", "addressed_risks": 0, "remaining_risks": len(original_risks)}
    
    hardened_code = gemini_response.get("hardened_code", [])
    addressed_risks = 0
    remaining_risks = []
    
    # Analyze each original risk against hardened code
    for risk in original_risks:
        risk_addressed = False
        
        # Check if hardened code contains patterns that address this risk
        for code_line in hardened_code:
            if isinstance(code_line, str):
                # Look for validation patterns
                if any(pattern in code_line.lower() for pattern in ["validate", "sanitize", "check", "verify"]):
                    if risk.risk_type in code_line.lower() or risk.severity in code_line.lower():
                        risk_addressed = True
                        break
                
                # Look for specific function replacements
                if risk.message and any(func in risk.message for func in ["eval", "exec", "subprocess"]):
                    if any(safe_func in code_line.lower() for safe_func in ["ast.literal_eval", "function", "subprocess.run"]):
                        risk_addressed = True
                        break
        
        if risk_addressed:
            addressed_risks += 1
        else:
            remaining_risks.append(risk)
    
    effectiveness = "high" if addressed_risks >= len(original_risks) * 0.8 else \
                   "medium" if addressed_risks >= len(original_risks) * 0.5 else "low"
    
    return {
        "effectiveness": effectiveness,
        "addressed_risks": addressed_risks,
        "remaining_risks": len(remaining_risks),
        "total_risks": len(original_risks),
        "remaining_risk_details": remaining_risks
    }

def repair_json(text: str) -> str:
    """Basic JSON repair for common Gemini output issues"""
    
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
        
        # Fix common Gemini JSON issues
        return fix_json_syntax(extracted)
    
    # Fallback: look for JSON object boundaries
    start = text.find('{')
    end = text.rfind('}')
    
    if start == -1 or end == -1:
        return text
    
    extracted = text[start:end+1].strip()
    return fix_json_syntax(extracted)

def fix_json_syntax(json_text: str) -> str:
    """Fix common JSON syntax issues from Gemini's output"""
    
    # Gemini sometimes puts actual Python code with triple quotes in JSON strings
    # We need to escape these properly for JSON
    
    # First, handle the case where Gemini puts unescaped triple quotes
    # Replace """...""" with properly escaped JSON string
    def replace_triple_quotes(match):
        content = match.group(1)
        # Escape quotes and newlines for JSON
        escaped = content.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
        return f'"{escaped}"'
    
    # Handle unescaped triple quotes
    json_text = re.sub(r'"""(.*?)"""', replace_triple_quotes, json_text, flags=re.DOTALL)
    
    # Handle the case where Gemini puts template strings that break JSON structure
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
            # This is a common pattern Gemini uses that breaks JSON
            continue
        else:
            fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def parse_guardrail_response(raw_output: str) -> dict:
    """Parse Gemini's response with robust error handling and schema validation"""
    
    if not isinstance(raw_output, str):
        raise ValueError("Expected string response from Gemini")
    
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
                    raise ValueError("Could not parse JSON from Gemini's response")
            else:
                                  raise ValueError("No JSON object found in Gemini's response")
    
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
            safe_print(f"[WARNING] Missing field '{field}', using default: {default}")
            parsed[field] = default
    
    return parsed

def get_guardrails(agent_data, tool_data, routing_logic, retrieved_context=""):
    """Get security guardrails from Gemini using Google Gemini API"""
    system_prompt = "You are a security expert specializing in LLM agent auditing. Your task is to scan AI agent systems for vulnerabilities and generate precise, actionable security guardrails in structured JSON format."

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

    Then write Python code that mitigates these risks. DO NOT USE ANY EMOJIS.
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
- Keep descriptions around 200 words each
- DO NOT ENCODE ANY EMOJIS.
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
        # Fix: Access the correct response text property for Google Gemini API
        if hasattr(response, 'candidates') and response.candidates:
            response_text = response.candidates[0].content.parts[0].text
        elif hasattr(response, 'text'):
            response_text = response.text
        else:
            response_text = str(response)
        return parse_guardrail_response(response_text)
    except ValueError as e:
        safe_print(f"[ERROR] Failed to parse Gemini's response: {e}")
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
    
    routing_logic = code  # send the whole agent logic to Gemini
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
    
        safe_print(f"[CHECK] Guardrails injected into {yaml_path}")

def load_threats(filepath=None):
    """Load threat data from markdown file"""
    if filepath is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(base_dir, "threat_list/owasp_top_10.md")
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        
        threats = []
        lines = content.split('\n')
        current_threat = None
        current_content = []
        
        for line in lines:
            # Check if this is a threat section header (#### 1. Agentic AI Tool Misuse)
            if line.strip().startswith('#### ') and any(char.isdigit() for char in line[:10]):
                # Save previous threat if exists
                if current_threat and current_content:
                    threats.append({
                        "title": current_threat,
                        "text": "\n".join(current_content).strip()
                    })
                
                # Start new threat
                current_threat = line.strip().replace('#### ', '').strip()
                current_content = []
            
            # Add content to current threat
            elif current_threat and line.strip():
                # Skip formatting markers and non-content sections
                skip_markers = ['######', '**Figure', '**References**', '**Example ATTACK SCENARIOS**']
                if not any(line.strip().startswith(marker) for marker in skip_markers):
                    current_content.append(line)
        
        # Add the last threat
        if current_threat and current_content:
            threats.append({
                "title": current_threat,
                "text": "\n".join(current_content).strip()
            })
        
        safe_print(f"[CHECK] Loaded {len(threats)} threats from OWASP file")
        return threats
        
    except FileNotFoundError:
        safe_print(f"[WARNING] Threat file not found: {filepath}")
        return []
    except Exception as e:
        safe_print(f"[WARNING] Error loading threats: {e}")
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
        safe_print(f"[WARNING] Context retrieval failed: {e}")
        return ""

def send_results_to_webapp(results):
    """Send scan results to the web application"""
    # Try HTTP communication first
    try:
        import requests
        
        # Web app URL (default to localhost:5001)
        webapp_url = os.environ.get("WEBAPP_URL", "http://localhost:5001")
        api_endpoint = f"{webapp_url}/api/scan"
        
        # Send POST request with results
        response = requests.post(
            api_endpoint,
            json=results,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        
        if response.status_code == 200:
            safe_print(f"[CHECK] Results sent to web app at {webapp_url}")
            return True
        else:
            safe_print(f"[WARNING] Web app returned status {response.status_code}")
            return False
            
    except ImportError:
        safe_print("[WARNING] Requests library not available. Install with: pip install requests")
    except requests.exceptions.ConnectionError:
        safe_print("[WARNING] Web app not running. Start with: python app.py")
    except Exception as e:
        safe_print(f"[WARNING] Error sending results to web app: {e}")
    
    # Fallback: Use file-based communication
    try:
        import json
        from datetime import datetime
        
        # Create a shared results file
        results_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "latest_scan_results.json")
        
        # Add timestamp if not present
        if 'timestamp' not in results:
            results['timestamp'] = datetime.now().isoformat()
        
        # Write results to file
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        safe_print(f"[CHECK] Results saved to file: {results_file}")
        safe_print("[INFO] Web app will read from this file on next refresh")
        return True
        
    except Exception as e:
        safe_print(f"[ERROR] Failed to save results to file: {e}")
        return False

# --- End inlined dependencies ---

mcp = FastMCP(name="AutohardenerServer")

@mcp.tool
def autoharden_agent(agent_path: str) -> dict:
    """Analyze and harden an AI agent with security guardrails - Windows Compatible"""
    try:
        safe_print(f"Analyzing: {agent_path}")
        
        # Check if path exists
        if not os.path.exists(agent_path):
            return {
                "error": f"Path not found: {agent_path}",
                "success": False
            }
        
        # Check if it's a directory
        if os.path.isdir(agent_path):
            return {
                "error": f"Path is a directory: {agent_path}. Use autoharden_directory() for directory scanning, or provide a specific Python file path.",
                "success": False,
                "suggestion": "Use autoharden_directory() to scan all Python files in a directory, or provide a specific .py file path."
            }
        
        # Check if it's a Python file
        if not agent_path.endswith('.py'):
            return {
                "error": f"File is not a Python file: {agent_path}",
                "success": False,
                "suggestion": "Please provide a .py file path for analysis."
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
        
        # Get guardrails from Gemini
        safe_print("[BRAIN] Generating guardrail suggestions...")
        parsed = get_guardrails(agent_card_str, tool_schema_str, routing_logic, retrieved_context)
        
        if not parsed:
            return {
                "error": "Failed to generate guardrails",
                "success": False
            }
        
        # Apply hybrid security analysis and annotations
        safe_print("[LOCK] Applying hybrid security analysis...")
        analyze_and_comment_codebase(root_dir, parsed)
        
        # Build agent context for additional analysis
        agent_context = build_agent_context(parsed)
        
        # Perform context-aware static analysis
        safe_print("[TARGET] Performing context-aware static analysis...")
        static_risks = scan_codebase_for_patterns(root_dir, agent_context)
        
        # Analyze hardened code effectiveness
        safe_print("[CHART] Analyzing hardened code effectiveness...")
        effectiveness_analysis = analyze_hardened_code_effectiveness(static_risks, parsed)
        
        # Inject guardrails into YAML if requested
        if os.path.exists(yaml_path):
            inject_guardrails_yaml(yaml_path, parsed)
        
        # Format results for display
        constraints = parsed.get("constraints", [])
        risks = parsed.get("risks", [])
        
        # Count context-enhanced risks
        context_enhanced_risks = [r for r in static_risks if "context" in r.suggestion.lower() or "agent" in r.suggestion.lower()]
        
        result = {
            "success": True,
            "file_path": file_path,
            "yaml_path": yaml_path,
            "yaml_exists": os.path.exists(yaml_path),
            "constraints_count": len(constraints),
            "risks_count": len(risks),
            "static_risks_count": len(static_risks),
            "context_enhanced_risks_count": len(context_enhanced_risks),
            "constraints": constraints,
            "risks": risks,
            "hardened_code": parsed.get("hardened_code", []),
            "agent_context": {
                "has_prompt_injection_risk": agent_context.has_prompt_injection_risk,
                "uses_dynamic_tool_routing": agent_context.uses_dynamic_tool_routing,
                "has_code_execution_capability": agent_context.has_code_execution_capability,
                "has_file_system_access": agent_context.has_file_system_access,
                "has_network_access": agent_context.has_network_access,
                "severity_multipliers": agent_context.severity_multipliers
            },
            "effectiveness_analysis": effectiveness_analysis,
            "message": f"Successfully analyzed and hardened {os.path.basename(file_path)} with hybrid LLM-augmented static analysis"
        }
        
        # Send results to web app if available
        try:
            send_results_to_webapp(result)
        except Exception as e:
            safe_print(f"[WARNING] Could not send results to web app: {e}")
        
        return result
        
    except Exception as e:
        return {
            "error": str(e),
            "success": False,
            "file_path": agent_path
        }

@mcp.tool
def autoharden_directory(directory_path: str) -> dict:
    """Analyze and harden all Python agents in a directory with hybrid LLM-augmented static analysis"""
    try:
        safe_print(f"Analyzing directory: {directory_path}")
        
        # Check if path exists
        if not os.path.exists(directory_path):
            return {
                "error": f"Directory not found: {directory_path}",
                "success": False
            }
        
        # Check if it's a directory
        if not os.path.isdir(directory_path):
            return {
                "error": f"Path is not a directory: {directory_path}",
                "success": False,
                "suggestion": "Use autoharden_agent() for single file analysis."
            }
        
        # Find all Python files
        python_files = list(Path(directory_path).rglob("*.py"))
        
        if not python_files:
            return {
                "error": f"No Python files found in directory: {directory_path}",
                "success": False
            }
        
        safe_print(f"[FOLDER] Found {len(python_files)} Python files to analyze")
        
        # Analyze each file
        results = []
        total_risks = 0
        total_context_enhanced = 0
        
        for file_path in python_files:
            try:
                safe_print(f"\nAnalyzing: {file_path}")
                
                # Get the root directory for this file
                file_root_dir = str(file_path.parent)
                yaml_path = str(file_path).replace(".py", "_card.yaml")
                
                # Retrieve security context
                retrieved_context = retrieve_context("prompt injection, tool misuse, agent execution")
                
                # Extract metadata
                agent_card, tool_schema, routing_logic = extract_metadata_from_file(str(file_path))
                agent_card_str = json.dumps(agent_card, indent=2)
                tool_schema_str = json.dumps(tool_schema, indent=2)
                
                # Get guardrails from Gemini
                safe_print("[BRAIN] Generating guardrail suggestions...")
                parsed = get_guardrails(agent_card_str, tool_schema_str, routing_logic, retrieved_context)
                
                if not parsed:
                    safe_print(f"[WARNING] Failed to generate guardrails for {file_path}")
                    continue
                
                # Apply hybrid security analysis
                safe_print("[LOCK] Applying hybrid security analysis...")
                analyze_and_comment_codebase(file_root_dir, parsed)
                
                # Build agent context
                agent_context = build_agent_context(parsed)
                
                # Perform context-aware static analysis
                safe_print("[TARGET] Performing context-aware static analysis...")
                static_risks = scan_codebase_for_patterns(file_root_dir, agent_context)
                
                # Analyze effectiveness
                effectiveness_analysis = analyze_hardened_code_effectiveness(static_risks, parsed)
                
                # Inject guardrails into YAML if it exists
                if os.path.exists(yaml_path):
                    inject_guardrails_yaml(yaml_path, parsed)
                
                # Count context-enhanced risks
                context_enhanced_risks = [r for r in static_risks if "context" in r.suggestion.lower() or "agent" in r.suggestion.lower()]
                
                file_result = {
                    "file_path": str(file_path),
                    "yaml_path": yaml_path,
                    "yaml_exists": os.path.exists(yaml_path),
                    "constraints_count": len(parsed.get("constraints", [])),
                    "risks_count": len(parsed.get("risks", [])),
                    "static_risks_count": len(static_risks),
                    "context_enhanced_risks_count": len(context_enhanced_risks),
                    "agent_context": {
                        "has_prompt_injection_risk": agent_context.has_prompt_injection_risk,
                        "uses_dynamic_tool_routing": agent_context.uses_dynamic_tool_routing,
                        "has_code_execution_capability": agent_context.has_code_execution_capability,
                        "severity_multipliers": agent_context.severity_multipliers
                    },
                    "effectiveness_analysis": effectiveness_analysis,
                    "success": True
                }
                
                results.append(file_result)
                total_risks += len(static_risks)
                total_context_enhanced += len(context_enhanced_risks)
                
                safe_print(f"[CHECK] Completed analysis of {file_path.name}")
                
            except Exception as e:
                safe_print(f"[ERROR] Failed to analyze {file_path}: {e}")
                results.append({
                    "file_path": str(file_path),
                    "success": False,
                    "error": str(e)
                })
        
        # Summary statistics
        successful_analyses = [r for r in results if r.get("success", False)]
        failed_analyses = [r for r in results if not r.get("success", False)]
        
        # Calculate directory-wide context insights
        high_risk_agents = [r for r in successful_analyses if r.get("agent_context", {}).get("has_prompt_injection_risk") or r.get("agent_context", {}).get("uses_dynamic_tool_routing")]
        
        return {
            "success": True,
            "directory_path": directory_path,
            "total_files": len(python_files),
            "successful_analyses": len(successful_analyses),
            "failed_analyses": len(failed_analyses),
            "total_risks_found": total_risks,
            "total_context_enhanced_risks": total_context_enhanced,
            "high_risk_agents": len(high_risk_agents),
            "file_results": results,
            "summary": {
                "average_risks_per_file": total_risks / len(successful_analyses) if successful_analyses else 0,
                "context_enhancement_rate": total_context_enhanced / total_risks if total_risks > 0 else 0,
                "high_risk_rate": len(high_risk_agents) / len(successful_analyses) if successful_analyses else 0
            },
            "message": f"Successfully analyzed {len(successful_analyses)}/{len(python_files)} files in {directory_path}"
        }
        
    except Exception as e:
        return {
            "error": str(e),
            "success": False,
            "directory_path": directory_path
        }



@mcp.tool
def ping_pong(random_string: str = "test") -> dict:
    """A dummy tool that returns pong."""
    return {"response": "pong", "input": random_string}

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='MCP Security Scanner')
    parser.add_argument('--scan-file', type=str, help='Scan a single agent file')
    parser.add_argument('--scan-directory', type=str, help='Scan a directory of agents')
    parser.add_argument('--server', action='store_true', help='Run as MCP server')
    
    args = parser.parse_args()
    
    if args.scan_file:
        # Run single file scan
        result = autoharden_agent(args.scan_file)
        print(json.dumps(result, indent=2))
        # Send results to webapp
        send_results_to_webapp(result)
    elif args.scan_directory:
        # Run directory scan
        result = autoharden_directory(args.scan_directory)
        print(json.dumps(result, indent=2))
        # Send results to webapp
        send_results_to_webapp(result)
    else:
        # Run as MCP server
        mcp.run() 
