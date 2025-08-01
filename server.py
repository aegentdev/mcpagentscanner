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
from datetime import datetime

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

class StaticRiskDetector(ast.NodeVisitor):
    """Enhanced AST visitor that detects comprehensive security patterns"""
    
    # Critical security risks - immediate action required
    CRITICAL_CALLS = {
        # Code execution risks
        'eval': 'Avoid eval: use ast.literal_eval or safe parsing',
        'exec': 'Avoid exec: use function dispatch or sandboxing',
        'compile': 'Avoid compile with user input: validate code source',
        '__import__': 'Avoid dynamic imports: use importlib safely',
        'globals': 'Avoid globals() access: use explicit variable passing',
        'locals': 'Avoid locals() access: use explicit variable passing',
        
        # System operation risks
        'subprocess.call': 'Validate shell commands and avoid shell=True',
        'subprocess.run': 'Validate shell commands and avoid shell=True',
        'subprocess.Popen': 'Validate shell commands and avoid shell=True',
        'os.system': 'Use subprocess with argument lists instead',
        'os.popen': 'Use subprocess with argument lists instead',
        'os.remove': 'Validate file paths to prevent directory traversal',
        'os.unlink': 'Validate file paths to prevent directory traversal',
        'shutil.rmtree': 'Validate paths and use absolute paths only',
        'shutil.copy': 'Validate source and destination paths',
        'shutil.move': 'Validate source and destination paths',
        
        # Network and file risks
        'urllib.request.urlopen': 'Validate URLs and use HTTPS',
        'requests.get': 'Validate URLs and use HTTPS',
        'requests.post': 'Validate URLs and use HTTPS',
        'requests.request': 'Validate URLs and use HTTPS',
        
        # Database risks
        'sqlite3.connect': 'Use parameterized queries to prevent SQL injection',
        'cursor.execute': 'Use parameterized queries to prevent SQL injection',
        'cursor.executemany': 'Use parameterized queries to prevent SQL injection',
    }
    
    # Medium security risks - review and fix
    MEDIUM_RISK_PATTERNS = {
        # AI/LLM specific risks
        'bind_tools': 'Validate tools before binding to LLM',
        'tools_by_name': 'Sanitize tool names from user input',
        'get_tool': 'Validate tool names from user input',
        'run_tool': 'Validate tool inputs and outputs',
        'invoke_tool': 'Validate tool inputs and outputs',
        
        # File operations
        'open': 'Sanitize file paths and restrict destinations',
        'file': 'Sanitize file paths and restrict destinations',
        'Path': 'Validate file paths to prevent directory traversal',
        'pathlib.Path': 'Validate file paths to prevent directory traversal',
        
        # Configuration and environment
        'os.environ': 'Validate environment variables',
        'os.getenv': 'Validate environment variables',
        'config.get': 'Validate configuration values',
        'yaml.load': 'Use yaml.safe_load instead',
        'json.loads': 'Validate JSON input size and structure',
        'pickle.loads': 'Avoid pickle: use safe serialization',
        'pickle.load': 'Avoid pickle: use safe serialization',
        
        # Template and string risks
        'jinja2.Template': 'Validate template variables',
        'string.Template': 'Validate template variables',
        'str.format': 'Validate format strings',
        'f-string': 'Validate f-string variables',
        
        # Network and API risks
        'httpx.get': 'Validate URLs and use HTTPS',
        'httpx.post': 'Validate URLs and use HTTPS',
        'aiohttp.ClientSession': 'Validate URLs and use HTTPS',
        'websocket.connect': 'Validate WebSocket URLs',
    }
    
    # Low security risks - monitor and improve
    LOW_RISK_PATTERNS = {
        'print': 'Consider logging instead of print for production',
        'logging.info': 'Validate log messages for sensitive data',
        'logging.debug': 'Validate log messages for sensitive data',
        'logging.error': 'Validate log messages for sensitive data',
        'datetime.now': 'Consider timezone awareness',
        'time.time': 'Consider timezone awareness',
        'random.random': 'Use secrets module for cryptographic randomness',
        'random.choice': 'Use secrets module for cryptographic randomness',
    }
    
    # Import risks - check for dangerous modules
    DANGEROUS_IMPORTS = {
        'pickle': 'Use safe serialization like json or msgpack',
        'marshal': 'Use safe serialization like json or msgpack',
        'shelve': 'Use safe serialization like json or msgpack',
        'tempfile': 'Validate temporary file usage',
        'mktemp': 'Use mkstemp instead for secure temp files',
    }
    
    # Variable assignment risks
    DANGEROUS_ASSIGNMENTS = {
        '__builtins__': 'Avoid modifying builtins',
        '__globals__': 'Avoid modifying globals',
        '__dict__': 'Validate dictionary modifications',
    }
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.risks: List[Risk] = []
        self.imports = set()
        self.variables = set()
        self.functions = set()
        self.classes = set()
        
    def visit_Import(self, node: ast.Import) -> None:
        """Detect dangerous imports"""
        for alias in node.names:
            module_name = alias.name.split('.')[0]  # Get base module name
            if module_name in self.DANGEROUS_IMPORTS:
                self.risks.append(Risk(
                    file_path=self.file_path,
                    line_number=getattr(node, 'lineno', 0),
                    risk_type='dangerous_import',
                    severity='medium',
                    message=f'⚠️ Dangerous import: {module_name}',
                    suggestion=self.DANGEROUS_IMPORTS[module_name],
                    source='static'
                ))
            self.imports.add(module_name)
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Detect dangerous from imports"""
        if node.module:
            module_name = node.module.split('.')[0]
            if module_name in self.DANGEROUS_IMPORTS:
                self.risks.append(Risk(
                    file_path=self.file_path,
                    line_number=getattr(node, 'lineno', 0),
                    risk_type='dangerous_import',
                    severity='medium',
                    message=f'⚠️ Dangerous import: from {module_name}',
                    suggestion=self.DANGEROUS_IMPORTS[module_name],
                    source='static'
                ))
            self.imports.add(module_name)
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect dangerous variable assignments"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if var_name in self.DANGEROUS_ASSIGNMENTS:
                    self.risks.append(Risk(
                        file_path=self.file_path,
                        line_number=getattr(node, 'lineno', 0),
                        risk_type='dangerous_assignment',
                        severity='critical',
                        message=f'🚨 Dangerous assignment: {var_name}',
                        suggestion=self.DANGEROUS_ASSIGNMENTS[var_name],
                        source='static'
                    ))
                self.variables.add(var_name)
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze function definitions for security issues"""
        self.functions.add(node.name)
        
        # Check for dangerous function names
        dangerous_funcs = ['eval', 'exec', 'system', 'shell', 'command']
        if any(dangerous in node.name.lower() for dangerous in dangerous_funcs):
            self.risks.append(Risk(
                file_path=self.file_path,
                line_number=getattr(node, 'lineno', 0),
                risk_type='dangerous_function_name',
                severity='medium',
                message=f'⚠️ Suspicious function name: {node.name}',
                suggestion='Review function implementation for security issues',
                source='static'
            ))
        
        # Check function arguments for potential injection points
        for arg in node.args.args:
            if arg.arg in ['user_input', 'data', 'content', 'payload', 'query']:
                self.risks.append(Risk(
                    file_path=self.file_path,
                    line_number=getattr(node, 'lineno', 0),
                    risk_type='potential_injection',
                    severity='medium',
                    message=f'⚠️ Potential injection point: {arg.arg} parameter',
                    suggestion='Validate and sanitize user input before processing',
                    source='static'
                ))
        
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Analyze class definitions"""
        self.classes.add(node.name)
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Enhanced function call analysis"""
        line_no = getattr(node, 'lineno', 0)
        
        # Get function name and check for risks
        func_name = self._get_function_name(node)
        if func_name:
            self._check_risk_patterns(func_name, line_no, node)
        
        # Check for string formatting risks
        self._check_string_formatting_risks(node, line_no)
        
        # Check for shell command risks
        self._check_shell_command_risks(node, line_no)
        
        # Check for file path risks
        self._check_file_path_risks(node, line_no)
        
        self.generic_visit(node)
    
    def _get_function_name(self, node: ast.Call) -> str:
        """Extract function name from call node with enhanced detection"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Handle module.function or obj.method calls
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                # Handle nested attributes like module.submodule.function
                return f"{self._get_attribute_chain(node.func.value)}.{node.func.attr}"
            return node.func.attr
        return ""
    
    def _get_attribute_chain(self, node: ast.Attribute) -> str:
        """Get full attribute chain for nested attributes"""
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        elif isinstance(node.value, ast.Attribute):
            return f"{self._get_attribute_chain(node.value)}.{node.attr}"
        return node.attr
    
    def _check_risk_patterns(self, func_name: str, line_no: int, node: ast.Call) -> None:
        """Enhanced risk pattern checking with context analysis"""
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
        
        # Medium risks
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
        
        # Low risks
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
    
    def _check_string_formatting_risks(self, node: ast.Call, line_no: int) -> None:
        """Check for string formatting security risks"""
        func_name = self._get_function_name(node)
        
        if func_name in ['str.format', 'format'] and node.args:
            # Check if format string contains user input
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.variables:
                    self.risks.append(Risk(
                        file_path=self.file_path,
                        line_number=line_no,
                        risk_type='format_string_injection',
                        severity='medium',
                        message=f'⚠️ Format string injection risk: {arg.id}',
                        suggestion='Validate format strings and escape user input',
                        source='static'
                    ))
    
    def _check_shell_command_risks(self, node: ast.Call, line_no: int) -> None:
        """Check for shell command injection risks"""
        func_name = self._get_function_name(node)
        
        if func_name in ['subprocess.call', 'subprocess.run', 'subprocess.Popen', 'os.system']:
            # Check if shell=True is used
            for keyword in node.keywords:
                if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        self.risks.append(Risk(
                            file_path=self.file_path,
                            line_number=line_no,
                            risk_type='shell_injection',
                            severity='critical',
                            message=f'🚨 Shell injection risk: shell=True detected',
                            suggestion='Use argument lists instead of shell=True',
                            source='static'
                        ))
            
            # Check if command contains user input
            if node.args and isinstance(node.args[0], ast.Name):
                if node.args[0].id in self.variables:
                    self.risks.append(Risk(
                        file_path=self.file_path,
                        line_number=line_no,
                        risk_type='command_injection',
                        severity='critical',
                        message=f'🚨 Command injection risk: {node.args[0].id}',
                        suggestion='Validate and sanitize command arguments',
                        source='static'
                    ))
    
    def _check_file_path_risks(self, node: ast.Call, line_no: int) -> None:
        """Check for file path traversal risks"""
        func_name = self._get_function_name(node)
        
        file_ops = ['open', 'os.remove', 'os.unlink', 'shutil.rmtree', 'shutil.copy', 'shutil.move']
        if func_name in file_ops and node.args:
            # Check if file path contains user input
            if isinstance(node.args[0], ast.Name) and node.args[0].id in self.variables:
                self.risks.append(Risk(
                    file_path=self.file_path,
                    line_number=line_no,
                    risk_type='path_traversal',
                    severity='critical',
                    message=f'🚨 Path traversal risk: {node.args[0].id}',
                    suggestion='Validate file paths and use absolute paths',
                    source='static'
                ))

def scan_codebase_for_patterns(root_dir: str) -> List[Risk]:
    """Enhanced scan with comprehensive security analysis"""
    all_risks = []
    
    # Walk through Python files
    for file_path in Path(root_dir).rglob("*.py"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content)
            detector = StaticRiskDetector(str(file_path))
            detector.visit(tree)
            
            # Add file-specific risks
            file_risks = detector.risks
            
            # Additional analysis
            file_risks.extend(_analyze_file_content(str(file_path), content))
            file_risks.extend(_analyze_dependencies(str(file_path), content))
            file_risks.extend(_analyze_configuration(str(file_path), content))
            
            all_risks.extend(file_risks)
            
        except Exception as e:
            print(f"⚠️ Error analyzing {file_path}: {e}")
    
    # Add project-level analysis
    all_risks.extend(_analyze_project_structure(root_dir))
    
    return all_risks

def _analyze_file_content(file_path: str, content: str) -> List[Risk]:
    """Analyze file content for security issues"""
    risks = []
    
    # Check for hardcoded secrets
    secret_patterns = [
        r'password\s*=\s*["\'][^"\']+["\']',
        r'api_key\s*=\s*["\'][^"\']+["\']',
        r'secret\s*=\s*["\'][^"\']+["\']',
        r'token\s*=\s*["\'][^"\']+["\']',
        r'private_key\s*=\s*["\'][^"\']+["\']',
    ]
    
    for i, line in enumerate(content.split('\n'), 1):
        for pattern in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                risks.append(Risk(
                    file_path=file_path,
                    line_number=i,
                    risk_type='hardcoded_secret',
                    severity='critical',
                    message=f'🚨 Hardcoded secret detected',
                    suggestion='Use environment variables or secure configuration management',
                    source='static'
                ))
    
    # Check for debug code in production
    debug_patterns = [
        r'import\s+pdb',
        r'pdb\.set_trace\(\)',
        r'breakpoint\(\)',
        r'print\s*\(',
        r'debug\s*=\s*True',
    ]
    
    for i, line in enumerate(content.split('\n'), 1):
        for pattern in debug_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                risks.append(Risk(
                    file_path=file_path,
                    line_number=i,
                    risk_type='debug_code',
                    severity='low',
                    message=f'ℹ️ Debug code detected',
                    suggestion='Remove debug code before production deployment',
                    source='static'
                ))
    
    # Check for SQL injection patterns
    sql_patterns = [
        r'execute\s*\(\s*["\'][^"\']*\+',
        r'execute\s*\(\s*f["\'][^"\']*\{[^}]*\}',
        r'execute\s*\(\s*["\'][^"\']*%s',
    ]
    
    for i, line in enumerate(content.split('\n'), 1):
        for pattern in sql_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                risks.append(Risk(
                    file_path=file_path,
                    line_number=i,
                    risk_type='sql_injection',
                    severity='critical',
                    message=f'🚨 Potential SQL injection detected',
                    suggestion='Use parameterized queries instead of string concatenation',
                    source='static'
                ))
    
    return risks

def _analyze_dependencies(file_path: str, content: str) -> List[Risk]:
    """Analyze dependencies for security issues"""
    risks = []
    
    # Check for known vulnerable packages
    vulnerable_packages = {
        'requests': '2.28.0',  # Example version check
        'urllib3': '1.26.0',
        'cryptography': '3.4.0',
    }
    
    # Extract import statements
    import_pattern = r'^(?:from\s+(\w+)|import\s+(\w+))'
    
    for i, line in enumerate(content.split('\n'), 1):
        match = re.match(import_pattern, line.strip())
        if match:
            package = match.group(1) or match.group(2)
            if package in vulnerable_packages:
                risks.append(Risk(
                    file_path=file_path,
                    line_number=i,
                    risk_type='vulnerable_dependency',
                    severity='medium',
                    message=f'⚠️ Potentially vulnerable package: {package}',
                    suggestion=f'Update {package} to version {vulnerable_packages[package]} or later',
                    source='static'
                ))
    
    return risks

def _analyze_configuration(file_path: str, content: str) -> List[Risk]:
    """Analyze configuration for security issues"""
    risks = []
    
    # Check for insecure configuration patterns
    config_patterns = [
        (r'DEBUG\s*=\s*True', 'Debug mode enabled in production'),
        (r'ALLOWED_HOSTS\s*=\s*\[\s*["\']\*["\']\s*\]', 'Wildcard allowed hosts'),
        (r'SECRET_KEY\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret key'),
        (r'CORS_ORIGIN_ALLOW_ALL\s*=\s*True', 'CORS allows all origins'),
    ]
    
    for i, line in enumerate(content.split('\n'), 1):
        for pattern, message in config_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                risks.append(Risk(
                    file_path=file_path,
                    line_number=i,
                    risk_type='insecure_configuration',
                    severity='medium',
                    message=f'⚠️ {message}',
                    suggestion='Review and secure configuration settings',
                    source='static'
                ))
    
    return risks

def _analyze_project_structure(root_dir: str) -> List[Risk]:
    """Analyze project structure for security issues"""
    risks = []
    
    # Check for sensitive files
    sensitive_files = [
        '.env',
        'config.py',
        'settings.py',
        'secrets.json',
        'credentials.json',
        '.pem',
        '.key',
    ]
    
    for file_path in Path(root_dir).rglob("*"):
        if file_path.is_file():
            file_name = file_path.name
            if any(sensitive in file_name for sensitive in sensitive_files):
                risks.append(Risk(
                    file_path=str(file_path),
                    line_number=0,
                    risk_type='sensitive_file',
                    severity='medium',
                    message=f'⚠️ Sensitive file detected: {file_name}',
                    suggestion='Ensure sensitive files are not committed to version control',
                    source='static'
                ))
    
    # Check for missing security files
    security_files = [
        '.gitignore',
        'requirements.txt',
        'Dockerfile',
        'docker-compose.yml',
    ]
    
    for security_file in security_files:
        if not (Path(root_dir) / security_file).exists():
            risks.append(Risk(
                file_path=str(Path(root_dir) / security_file),
                line_number=0,
                risk_type='missing_security_file',
                severity='low',
                message=f'ℹ️ Missing security file: {security_file}',
                suggestion=f'Consider adding {security_file} for better security practices',
                source='static'
            ))
    
    return risks

def calculate_security_metrics(risks: List[Risk]) -> dict:
    """Calculate comprehensive security metrics"""
    total_risks = len(risks)
    
    # Count by severity
    critical_count = sum(1 for r in risks if r.severity == 'critical')
    medium_count = sum(1 for r in risks if r.severity == 'medium')
    low_count = sum(1 for r in risks if r.severity == 'low')
    
    # Count by risk type
    risk_types = {}
    for risk in risks:
        risk_types[risk.risk_type] = risk_types.get(risk.risk_type, 0) + 1
    
    # Count by source
    static_count = sum(1 for r in risks if r.source == 'static')
    gemini_count = sum(1 for r in risks if r.source == 'gemini')
    
    # Calculate risk score (weighted by severity)
    risk_score = (critical_count * 10) + (medium_count * 5) + (low_count * 1)
    
    # Determine overall security rating
    if risk_score == 0:
        security_rating = "A+"
    elif risk_score <= 10:
        security_rating = "A"
    elif risk_score <= 25:
        security_rating = "B"
    elif risk_score <= 50:
        security_rating = "C"
    elif risk_score <= 100:
        security_rating = "D"
    else:
        security_rating = "F"
    
    return {
        'total_risks': total_risks,
        'critical_count': critical_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'risk_types': risk_types,
        'static_count': static_count,
        'gemini_count': gemini_count,
        'risk_score': risk_score,
        'security_rating': security_rating,
        'files_analyzed': len(set(r.file_path for r in risks)),
    }

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
            message=f"📋 {constraint.get('description', 'No description')}",
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
            message=f"⚠️ {risk.get('description', 'No description')}",
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

def _insert_gemini_header(lines: List[str], gemini_response: dict) -> None:
    """Insert Gemini analysis header at the top of the file"""
    header = [
        "# 🤖 AI Security Analysis Summary\n",
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
    """Perform comprehensive security analysis and annotation with enhanced metrics"""
    print(f"🔍 Starting enhanced security analysis of: {root_dir}")
    
    # Phase 1: Enhanced static pattern detection
    print("📊 Phase 1: Enhanced static pattern detection...")
    static_risks = scan_codebase_for_patterns(root_dir)
    
    # Calculate static analysis metrics
    static_metrics = calculate_security_metrics(static_risks)
    
    print(f"   Found {static_metrics['total_risks']} static security patterns:")
    print(f"     🚨 Critical: {static_metrics['critical_count']}")
    print(f"     ⚠️ Medium: {static_metrics['medium_count']}")
    print(f"     ℹ️ Low: {static_metrics['low_count']}")
    print(f"     📁 Files analyzed: {static_metrics['files_analyzed']}")
    print(f"     📊 Security rating: {static_metrics['security_rating']}")
    
    # Phase 2: Integrate Gemini findings
    print("🤖 Phase 2: Integrating Gemini findings...")
    gemini_risks = []
    if gemini_response:
        gemini_risks = parse_gemini_findings(gemini_response)
        gemini_metrics = calculate_security_metrics(gemini_risks)
        
        print(f"   Gemini identified {gemini_metrics['total_risks']} additional risks:")
        print(f"     🚨 Critical: {gemini_metrics['critical_count']}")
        print(f"     ⚠️ Medium: {gemini_metrics['medium_count']}")
        print(f"     ℹ️ Low: {gemini_metrics['low_count']}")
    
    # Phase 3: Apply annotations
    print("✏️ Phase 3: Applying security comments...")
    risks_by_file = merge_risk_findings(static_risks, gemini_risks)
    files_to_annotate = [f for f in risks_by_file.keys() if f != "gemini_analysis"]
    print(f"   {len(files_to_annotate)} files need security annotations")
    
    apply_comments_to_files(risks_by_file, gemini_response)
    
    # Phase 4: Calculate comprehensive metrics
    print("📈 Phase 4: Calculating comprehensive security metrics...")
    all_risks = static_risks + gemini_risks
    comprehensive_metrics = calculate_security_metrics(all_risks)
    
    # Detailed risk type breakdown
    print(f"\n📋 Risk Type Breakdown:")
    for risk_type, count in comprehensive_metrics['risk_types'].items():
        print(f"     {risk_type}: {count}")
    
    # Security rating and recommendations
    print(f"\n🎯 Security Assessment:")
    print(f"   Overall Security Rating: {comprehensive_metrics['security_rating']}")
    print(f"   Risk Score: {comprehensive_metrics['risk_score']}")
    
    # Generate recommendations based on findings
    recommendations = _generate_security_recommendations(comprehensive_metrics, all_risks)
    print(f"\n💡 Security Recommendations:")
    for i, rec in enumerate(recommendations[:5], 1):  # Top 5 recommendations
        print(f"   {i}. {rec}")
    
    print("✅ Enhanced security analysis complete!")

def _generate_security_recommendations(metrics: dict, risks: List[Risk]) -> List[str]:
    """Generate actionable security recommendations based on analysis"""
    recommendations = []
    
    # Critical risk recommendations
    if metrics['critical_count'] > 0:
        recommendations.append("Address all critical security risks immediately")
        recommendations.append("Review and fix code execution vulnerabilities")
        recommendations.append("Implement proper input validation for all user inputs")
    
    # Medium risk recommendations
    if metrics['medium_count'] > 0:
        recommendations.append("Review and secure file operations")
        recommendations.append("Implement proper authentication and authorization")
        recommendations.append("Add input sanitization for all external data")
    
    # Configuration recommendations
    config_risks = [r for r in risks if r.risk_type == 'insecure_configuration']
    if config_risks:
        recommendations.append("Review and secure application configuration")
        recommendations.append("Use environment variables for sensitive configuration")
    
    # Dependency recommendations
    dep_risks = [r for r in risks if r.risk_type == 'vulnerable_dependency']
    if dep_risks:
        recommendations.append("Update vulnerable dependencies to latest secure versions")
        recommendations.append("Implement dependency vulnerability scanning")
    
    # General recommendations
    if metrics['security_rating'] in ['D', 'F']:
        recommendations.append("Conduct comprehensive security audit")
        recommendations.append("Implement security testing in CI/CD pipeline")
    
    recommendations.append("Consider implementing automated security scanning")
    recommendations.append("Establish security code review process")
    
    return recommendations

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
            print(f"⚠️  Missing field '{field}', using default: {default}")
            parsed[field] = default
    
    return parsed

def get_guardrails(agent_data, tool_data, routing_logic, retrieved_context=""):
    """Get security guardrails from Gemini using Google Gemini API"""
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
        # Fix: Access the correct response text property for Google Gemini API
        if hasattr(response, 'candidates') and response.candidates:
            response_text = response.candidates[0].content.parts[0].text
        elif hasattr(response, 'text'):
            response_text = response.text
        else:
            response_text = str(response)
        return parse_guardrail_response(response_text)
    except ValueError as e:
        print(f"❌ Failed to parse Gemini's response: {e}")
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
    
    print(f"✅ Guardrails injected into {yaml_path}")

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
        
        print(f"✅ Loaded {len(threats)} threats from OWASP file")
        return threats
        
    except FileNotFoundError:
        print(f"⚠️ Threat file not found: {filepath}")
        return []
    except Exception as e:
        print(f"⚠️ Error loading threats: {e}")
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

def send_results_to_webapp(results):
    """Send scan results to the web application"""
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
            print(f"✅ Results sent to web app at {webapp_url}")
        else:
            print(f"⚠️ Web app returned status {response.status_code}")
            
    except ImportError:
        print("⚠️ Requests library not available. Install with: pip install requests")
    except requests.exceptions.ConnectionError:
        print("⚠️ Web app not running. Start with: python app.py")
    except Exception as e:
        print(f"⚠️ Error sending results to web app: {e}")

def generate_security_report(risks: List[Risk], output_file: str = None) -> str:
    """Generate a comprehensive security report"""
    metrics = calculate_security_metrics(risks)
    
    report = f"""
# 🔒 Security Analysis Report

## 📊 Executive Summary
- **Overall Security Rating**: {metrics['security_rating']}
- **Risk Score**: {metrics['risk_score']}
- **Total Risks Identified**: {metrics['total_risks']}
- **Files Analyzed**: {metrics['files_analyzed']}

## 🚨 Critical Risks ({metrics['critical_count']})
"""
    
    critical_risks = [r for r in risks if r.severity == 'critical']
    for risk in critical_risks:
        report += f"""
### {risk.risk_type.replace('_', ' ').title()}
- **File**: {risk.file_path}
- **Line**: {risk.line_number}
- **Message**: {risk.message}
- **Suggestion**: {risk.suggestion}
"""
    
    report += f"""
## ⚠️ Medium Risks ({metrics['medium_count']})
"""
    
    medium_risks = [r for r in risks if r.severity == 'medium']
    for risk in medium_risks:
        report += f"""
### {risk.risk_type.replace('_', ' ').title()}
- **File**: {risk.file_path}
- **Line**: {risk.line_number}
- **Message**: {risk.message}
- **Suggestion**: {risk.suggestion}
"""
    
    report += f"""
## 📈 Risk Type Breakdown
"""
    
    for risk_type, count in metrics['risk_types'].items():
        report += f"- **{risk_type.replace('_', ' ').title()}**: {count}\n"
    
    report += f"""
## 💡 Recommendations
"""
    
    recommendations = _generate_security_recommendations(metrics, risks)
    for i, rec in enumerate(recommendations, 1):
        report += f"{i}. {rec}\n"
    
    report += f"""
## 📅 Report Generated
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"📄 Security report saved to: {output_file}")
    
    return report

def scan_dependencies_for_vulnerabilities(requirements_file: str = "requirements.txt") -> List[Risk]:
    """Scan dependencies for known vulnerabilities"""
    risks = []
    
    if not os.path.exists(requirements_file):
        return risks
    
    try:
        with open(requirements_file, 'r') as f:
            requirements = f.read()
        
        # Parse requirements
        for line in requirements.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Extract package name and version
                if '==' in line:
                    package, version = line.split('==', 1)
                elif '>=' in line:
                    package, version = line.split('>=', 1)
                elif '<=' in line:
                    package, version = line.split('<=', 1)
                else:
                    package = line
                    version = "unknown"
                
                package = package.strip()
                version = version.strip()
                
                # Check against known vulnerable versions
                if package in KNOWN_VULNERABLE_PACKAGES:
                    vulnerable_versions = KNOWN_VULNERABLE_PACKAGES[package]
                    if version in vulnerable_versions:
                        risks.append(Risk(
                            file_path=requirements_file,
                            line_number=0,
                            risk_type='vulnerable_dependency',
                            severity='critical',
                            message=f'🚨 Vulnerable dependency: {package} {version}',
                            suggestion=f'Update {package} to a secure version',
                            source='static'
                        ))
    
    except Exception as e:
        print(f"⚠️ Error scanning dependencies: {e}")
    
    return risks

# Known vulnerable package versions (example)
KNOWN_VULNERABLE_PACKAGES = {
    'requests': ['2.25.0', '2.25.1', '2.26.0'],
    'urllib3': ['1.26.0', '1.26.1', '1.26.2'],
    'cryptography': ['3.3.0', '3.3.1', '3.3.2'],
    'django': ['3.1.0', '3.1.1', '3.1.2'],
    'flask': ['2.0.0', '2.0.1', '2.0.2'],
}

def analyze_security_configuration(config_file: str) -> List[Risk]:
    """Analyze security configuration files"""
    risks = []
    
    if not os.path.exists(config_file):
        return risks
    
    try:
        with open(config_file, 'r') as f:
            content = f.read()
        
        # Check for common security misconfigurations
        security_checks = [
            (r'DEBUG\s*=\s*True', 'Debug mode enabled in production'),
            (r'ALLOWED_HOSTS\s*=\s*\[\s*["\']\*["\']\s*\]', 'Wildcard allowed hosts'),
            (r'SECRET_KEY\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret key'),
            (r'CORS_ORIGIN_ALLOW_ALL\s*=\s*True', 'CORS allows all origins'),
            (r'CSRF_COOKIE_SECURE\s*=\s*False', 'CSRF cookie not secure'),
            (r'SESSION_COOKIE_SECURE\s*=\s*False', 'Session cookie not secure'),
            (r'PASSWORD_HASHERS\s*=\s*\[[^\]]*["\']django\.contrib\.auth\.hashers\.MD5PasswordHasher["\'][^\]]*\]', 'MD5 password hashing'),
        ]
        
        for i, line in enumerate(content.split('\n'), 1):
            for pattern, message in security_checks:
                if re.search(pattern, line, re.IGNORECASE):
                    risks.append(Risk(
                        file_path=config_file,
                        line_number=i,
                        risk_type='insecure_configuration',
                        severity='medium',
                        message=f'⚠️ {message}',
                        suggestion='Review and secure configuration settings',
                        source='static'
                    ))
    
    except Exception as e:
        print(f"⚠️ Error analyzing configuration: {e}")
    
    return risks

def perform_comprehensive_security_audit(root_dir: str) -> dict:
    """Perform a comprehensive security audit"""
    print("🔍 Starting comprehensive security audit...")
    
    audit_results = {
        'static_analysis': [],
        'dependency_scan': [],
        'configuration_scan': [],
        'project_structure': [],
        'metrics': {},
        'recommendations': [],
        'report': ''
    }
    
    # 1. Static code analysis
    print("📊 Phase 1: Static code analysis...")
    audit_results['static_analysis'] = scan_codebase_for_patterns(root_dir)
    
    # 2. Dependency vulnerability scan
    print("📦 Phase 2: Dependency vulnerability scan...")
    requirements_file = os.path.join(root_dir, "requirements.txt")
    audit_results['dependency_scan'] = scan_dependencies_for_vulnerabilities(requirements_file)
    
    # 3. Configuration analysis
    print("⚙️ Phase 3: Configuration analysis...")
    config_files = ['settings.py', 'config.py', '.env', 'docker-compose.yml']
    for config_file in config_files:
        config_path = os.path.join(root_dir, config_file)
        if os.path.exists(config_path):
            audit_results['configuration_scan'].extend(analyze_security_configuration(config_path))
    
    # 4. Project structure analysis
    print("📁 Phase 4: Project structure analysis...")
    audit_results['project_structure'] = _analyze_project_structure(root_dir)
    
    # 5. Calculate comprehensive metrics
    print("📈 Phase 5: Calculating comprehensive metrics...")
    all_risks = (audit_results['static_analysis'] + 
                audit_results['dependency_scan'] + 
                audit_results['configuration_scan'] + 
                audit_results['project_structure'])
    
    audit_results['metrics'] = calculate_security_metrics(all_risks)
    audit_results['recommendations'] = _generate_security_recommendations(audit_results['metrics'], all_risks)
    
    # 6. Generate comprehensive report
    print("📄 Phase 6: Generating comprehensive report...")
    report_file = os.path.join(root_dir, "security_audit_report.md")
    audit_results['report'] = generate_security_report(all_risks, report_file)
    
    print("✅ Comprehensive security audit complete!")
    return audit_results

# --- End inlined dependencies ---

mcp = FastMCP(name="AutohardenerServer")

@mcp.tool
def autoharden_agent(agent_path: str) -> dict:
    """Analyze and harden an AI agent with security guardrails"""
    try:
        print(f"🔍 Analyzing: {agent_path}")
        
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
            "message": f"Successfully analyzed and hardened {os.path.basename(file_path)}"
        }
        
        # Send results to web app if available
        try:
            send_results_to_webapp(result)
        except Exception as e:
            print(f"⚠️ Could not send results to web app: {e}")
        
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

@mcp.tool
def comprehensive_security_audit(project_path: str) -> dict:
    """Perform a comprehensive security audit of a project"""
    try:
        print(f"🔍 Starting comprehensive security audit for: {project_path}")
        
        # Validate project path
        if not os.path.exists(project_path):
            return {
                "error": f"Project path not found: {project_path}",
                "success": False
            }
        
        # Perform comprehensive audit
        audit_results = perform_comprehensive_security_audit(project_path)
        
        # Send results to web app if available
        try:
            send_results_to_webapp({
                "audit_type": "comprehensive_security_audit",
                "project_path": project_path,
                "metrics": audit_results['metrics'],
                "total_risks": audit_results['metrics']['total_risks'],
                "security_rating": audit_results['metrics']['security_rating'],
                "recommendations": audit_results['recommendations'][:5],  # Top 5
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            print(f"⚠️ Could not send results to web app: {e}")
        
        return {
            "success": True,
            "project_path": project_path,
            "metrics": audit_results['metrics'],
            "recommendations": audit_results['recommendations'],
            "report_file": os.path.join(project_path, "security_audit_report.md"),
            "message": f"Comprehensive security audit completed for {project_path}"
        }
        
    except Exception as e:
        return {
            "error": str(e),
            "success": False,
            "project_path": project_path
        }

if __name__ == "__main__":
    mcp.run() 