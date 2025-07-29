# MCP Agent Scanner - AutoHardener

🔒 **AI Agent Security Hardening Tool**

A Model Context Protocol (MCP) server that automatically analyzes and hardens AI agents with security guardrails. This tool combines static code analysis with AI-powered security recommendations to identify vulnerabilities and suggest mitigations.

## 🚀 Features

- **Static Security Analysis**: Detects common security patterns in Python code
- **AI-Powered Recommendations**: Uses Google Gemini to identify agent-specific vulnerabilities
- **Automatic Code Annotation**: Adds security comments directly to your code
- **Risk Categorization**: Classifies risks as Critical, Medium, or Low severity
- **YAML Integration**: Injects security guardrails into agent card files
- **Threat Intelligence**: Incorporates OWASP Top 10 and other security frameworks
- **Modern Web Dashboard**: Beautiful React-based interface with real-time updates
- **Multi-Project Support**: Switch between different multi-agent projects
- **Interactive Scan History**: Click any scan for detailed analysis view
- **Responsive Design**: Optimized for desktop and mobile viewing

## 📋 Prerequisites

- Python 3.8+
- Node.js 16+ (for frontend)
- Google Gemini API key
- FastMCP framework

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/aegentdev/mcpagentscanner.git
cd mcpagentscanner
```

### 2. Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Node.js dependencies
npm install
```

Or install manually:

```bash
pip install fastmcp sentence-transformers faiss-cpu google-genai python-dotenv pyyaml
npm install react react-dom @types/react @types/react-dom vite @vitejs/plugin-react typescript
```

### 3. Set Up Environment Variables

Create a `.env` file in the project root:

```bash
# Required: Google Gemini API key
GOOGLE_API_KEY=your_gemini_api_key_here
```

### 4. Get Google Gemini API Key

1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Add it to your `.env` file

## 🚀 Usage

### ⚠️ IMPORTANT: You MUST Set Up MCP Client

**Before using this tool, you MUST configure an MCP client (like Claude Desktop) to connect to the server. The web dashboard is for viewing results only - all scanning is done through MCP clients.**

### Using with MCP Clients

The MCP Agent Scanner can be used with various MCP clients. Here's how to register it with different clients:

#### With Claude Desktop

1. **Open Claude Desktop Settings**
   - Go to Settings → MCP Servers
   - Click "Add Server"

2. **Configure the Server**
   ```json
   {
     "mcpServers": {
       "autohardener": {
         "command": "python",
         "args": ["/path/to/your/mcpagentscanner/server.py"],
         "env": {
           "GOOGLE_API_KEY": "your_api_key_here"
         }
       }
     }
   }
   ```

3. **Restart Claude Desktop**
4. **Use the `autoharden_agent` tool** to analyze your AI agents

#### With Cursor (VS Code)

1. **Open Cursor Settings**
   - Go to Settings → Extensions → MCP
   - Or add to your `settings.json`:

2. **Add MCP Configuration**
   ```json
   {
     "mcp.servers": {
       "autohardener": {
         "command": "python",
         "args": ["/path/to/your/mcpagentscanner/server.py"],
         "env": {
           "GOOGLE_API_KEY": "your_api_key_here"
         }
       }
     }
   }
   ```

3. **Restart Cursor**
4. **Access via Command Palette**: `MCP: List Tools`

#### With Other MCP Clients

**Available Tools:**
- **`autoharden_agent(agent_path: str)`**: Main security analysis tool
- **`ping_pong(random_string: str)`**: Health check tool

**Supported Clients:**
- **Claude Desktop**: Native MCP support
- **Cursor**: VS Code-based with MCP extension
- **Neovim**: Via MCP plugins
- **Emacs**: Via MCP packages
- **Custom Clients**: Any MCP-compatible client

**Configuration Format:**
```json
{
  "command": "python",
  "args": ["/absolute/path/to/mcpagentscanner/server.py"],
  "env": {
    "GOOGLE_API_KEY": "your_gemini_api_key"
  }
}
```

**Important Notes:**
- Use absolute paths for the server.py file
- Ensure your Google Gemini API key is set in the environment
- The server must be accessible from your MCP client
- Restart your MCP client after configuration changes

### Quick Start (Recommended)

**Note: The web dashboard only displays scan results. To perform scans, you must first set up an MCP client (see section above).**

```bash
# Build the frontend
npm run build

# Start the application
python3 app.py
```

Visit http://localhost:5001 to access the dashboard.

### Option 1: Run Everything Together

Use the dashboard runner to start both the MCP server and web interface:

```bash
python3 run_dashboard.py
```

This will start:
- **Web Dashboard** at http://localhost:5001 (for viewing results)
- **MCP Server** ready for connections (for performing scans via MCP clients)

### Option 2: Run Services Separately

#### Running the MCP Server Only

```bash
python3 server.py
```

The server will start and be ready to accept MCP connections.

#### Running the Web Dashboard Only

```bash
python3 web_app.py
```

The web dashboard will be available at http://localhost:5001

### 🖥️ Modern Web Dashboard

The MCP Scanner includes a modern React-based web dashboard with advanced features.

#### Dashboard Features

- **🎨 Modern React UI**: Beautiful, responsive design with Tailwind CSS
- **🌙 Dark/Light Mode**: Toggle between themes with the moon/sun icon
- **📊 Real-time Updates**: Automatically refreshes every 5 seconds
- **🚨 Severity Indicators**: Color-coded risk levels (Critical/Medium/Low)
- **📝 Code Highlighting**: Syntax-highlighted security recommendations
- **📚 Interactive Scan History**: Click any scan for detailed modal view
- **📈 Summary Cards**: Quick overview of risk counts and statistics
- **🧭 Full Navigation**: Complete sidebar navigation with all features
- **📁 Multi-Project Support**: Switch between different multi-agent projects
- **🔍 Detailed Analysis**: Modal popups for comprehensive scan details

#### Multi-Agent Projects

The dashboard includes a diverse set of multi-agent projects:

**Finance & Trading:**
- **Quantum Traders** - Multi-agent quantum trading system
- **Financial Advisor** - Investment portfolio optimization

**Science & Research:**
- **Bio Research Lab** - AI agents for drug discovery
- **Space Explorer** - Autonomous space mission planning
- **Climate Predictor** - Environmental modeling agents

**Technology & Security:**
- **Cyber Sentinel** - Advanced threat detection network

**Creative & Entertainment:**
- **Creative Studio** - AI-powered content generation
- **Game Developer** - Procedural game world generation

**Infrastructure & Healthcare:**
- **Smart City Hub** - Urban infrastructure management
- **Medical Diagnosis** - Healthcare diagnostic agents

#### Dashboard URLs

- **Main Dashboard**: http://localhost:5001
- **API Endpoint**: http://localhost:5001/api/scan
- **Latest Results**: http://localhost:5001/api/results
- **Scan History**: http://localhost:5001/api/history

#### Troubleshooting the Frontend

**Port 5001 already in use:**
```bash
# Kill any process using port 5001
pkill -f "python3 app.py"

# Or use a different port
python3 app.py --port 5002
```

**Dashboard not loading:**
```bash
# Check if the web app is running
curl http://localhost:5001/api/results

# Restart the web app
python3 app.py
```

**No data showing:**
```bash
# Send test data to verify the API
curl -X POST http://localhost:5001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"success":true,"message":"Test scan","constraints":[],"risks":[]}'
```

**Build errors:**
```bash
# Ensure Node.js and npm are installed
node --version
npm --version

# Install dependencies manually if needed
npm install
npm run build
```

### Using with MCP Clients

#### With Claude Desktop

1. Add the server to your MCP configuration:

```json
{
  "mcpServers": {
    "autohardener": {
      "command": "python",
      "args": ["/path/to/your/mcpagentscanner/server.py"],
      "env": {
        "GOOGLE_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

2. Restart Claude Desktop
3. Use the `autoharden_agent` tool to analyze your AI agents

#### With Other MCP Clients

The server provides two tools:

- `autoharden_agent(agent_path: str)`: Main security analysis tool
- `ping_pong(random_string: str)`: Health check tool

## 🔍 How It Works

### 1. Static Analysis Phase

The tool scans your codebase for known security patterns:

**Critical Risks:**
- `eval()`, `exec()`, `compile()` - Code execution vulnerabilities
- `subprocess.call()`, `os.system()` - Command injection risks
- `os.remove()`, `shutil.rmtree()` - File system vulnerabilities

**Medium Risks:**
- `bind_tools()`, `tools_by_name()` - Tool binding vulnerabilities
- `open()` - File operation risks

**Low Risks:**
- `requests.get()`, `urllib.request()` - Network security concerns

### 2. AI Analysis Phase

Uses Google Gemini to:
- Analyze agent architecture and purpose
- Identify prompt injection vulnerabilities
- Detect tool misuse patterns
- Suggest specific security mitigations

### 3. Code Annotation

Automatically adds security comments to your code:

```python
# 🚨 Critical: eval() detected
# 💡 Avoid eval: use ast.literal_eval or safe parsing
result = eval(user_input)  # Original line
```

### 4. YAML Integration

If a `*_card.yaml` file exists, security findings are injected:

```yaml
security:
  constraints:
    - description: "Validate all user inputs"
      severity: "critical"
  risks:
    - description: "Potential prompt injection"
      severity: "medium"
      impact: "Unauthorized code execution"
  suggested_guardrails:
    - "# Input validation function"
    - "def validate_input(user_input):"
    - "    return sanitized_input"
```

## 📊 Example Output

### Terminal Output
```
🔍 Starting security analysis of: /path/to/agent
📊 Phase 1: Static pattern detection...
   Found 5 static security patterns:
     🚨 Critical: 2
     ⚠️ Medium: 2
     ℹ️ Low: 1
🤖 Phase 2: Integrating Claude findings...
   Claude identified 3 additional risks:
     🚨 Critical: 1
     ⚠️ Medium: 1
     ℹ️ Low: 1
✏️ Phase 3: Applying security comments...
   3 files need security annotations
✅ Annotated 2 risks in agent.py
✅ Annotated 1 risks in utils.py
✅ Results sent to web app at http://localhost:5001

📋 Security Analysis Summary:
   Total risks identified: 8
   🚨 Critical: 3
   ⚠️ Medium: 3
   ℹ️ Low: 2
✅ Security analysis complete!
```

### Web Dashboard
The web dashboard provides a beautiful interface to view:
- **Real-time scan results** with severity indicators
- **Interactive scan history** with clickable entries
- **Security constraints and risks** with color-coded severity
- **Code recommendations** with syntax highlighting
- **Summary statistics** and metrics
- **Multi-project navigation** with diverse agent themes

## 🛡️ Security Features

### Risk Detection

- **Prompt Injection**: Identifies overly broad prompts and insufficient input validation
- **Tool Misuse**: Detects unsafe tool binding and execution patterns
- **Code Execution**: Flags dangerous eval/exec usage
- **File Operations**: Identifies path traversal and unsafe file handling
- **Network Security**: Highlights insecure API calls and data transmission

### Mitigation Strategies

- Input validation and sanitization
- Sandboxed execution environments
- Proper error handling and logging
- Secure tool binding patterns
- Access control and authentication

## 🔧 Configuration

### Customizing Risk Patterns

You can modify the risk patterns in the `StaticRiskDetector` class:

```python
CRITICAL_CALLS = {
    'your_risky_function': 'Your custom warning message',
    # ... existing patterns
}
```

### Adding Custom Threat Intelligence

Place additional threat markdown files in the `threat_list/` directory:

```markdown
## Your Custom Threat

Description of the threat and mitigation strategies.

---
```

## 🐛 Troubleshooting

### Common Issues

1. **"GOOGLE_API_KEY environment variable not set"**
   - Ensure your `.env` file exists and contains the API key
   - Verify the key is valid and has sufficient quota

2. **"Failed to analyze file"**
   - Check file permissions
   - Ensure the file is valid Python code
   - Verify the file path is correct

3. **"Failed to parse Claude's response"**
   - This usually indicates an API quota issue
   - Check your Google Gemini API usage
   - Verify your API key permissions

4. **"Port already in use"**
   ```bash
   pkill -f "python3 app.py"
   python3 app.py
   ```

### Debug Mode

Add debug logging by modifying the server:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Submit a pull request

## 📄 License

[Add your license information here]

## 🙏 Acknowledgments

- Built with [FastMCP](https://github.com/fastmcp/fastmcp)
- Powered by [Google Gemini](https://ai.google.dev/)
- Security patterns based on OWASP guidelines
- Threat intelligence from various security frameworks
- Modern UI built with React and Tailwind CSS

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Check the troubleshooting section
- Review the MCP documentation

---

**⚠️ Disclaimer**: This tool is for educational and security research purposes. Always review and test security recommendations before implementing them in production environments.
