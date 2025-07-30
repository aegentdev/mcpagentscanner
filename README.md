# MCP Agent Scanner - AutoHardener

AI Agent Security Hardening Tool using Model Context Protocol (MCP).

## Features

- Static security analysis of Python code
- AI-powered vulnerability detection using Google Gemini
- Risk categorization (Critical, Medium, Low)
- Web dashboard for viewing scan results
- MCP server for integration with AI clients

## Prerequisites

- Python 3.8+
- Node.js 16+
- Google Gemini API key

## Installation

1. Clone the repository
```bash
git clone https://github.com/aegentdev/mcpagentscanner.git
cd mcpagentscanner
```

2. Install dependencies
```bash
pip install -r requirements.txt
npm install
```

3. Set up environment variables
Create a `.env` file:
```
GOOGLE_API_KEY=your_gemini_api_key_here
```

## MCP Configuration

Configure your MCP client (Claude Desktop, Cursor, etc.) to connect to the server:

### Claude Desktop
Add to MCP Servers in settings:
```json
{
  "mcpServers": {
    "autohardener": {
      "command": "python",
      "args": ["/path/to/mcpagentscanner/server.py"],
      "env": {
        "GOOGLE_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### Cursor
Add to settings.json:
```json
{
  "mcp.servers": {
    "autohardener": {
      "command": "python",
      "args": ["/path/to/mcpagentscanner/server.py"],
      "env": {
        "GOOGLE_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

## Usage

### Available MCP Tools
- `autoharden_agent(agent_path: str)` - Analyze single Python file
- `autoharden_directory(directory_path: str)` - Analyze all Python files in directory
- `ping_pong(random_string: str)` - Health check

### Running the Components

1. Start MCP Server (Terminal 1)
```bash
python3 server.py
```

2. Start Web Dashboard (Terminal 2)
```bash
npm run build
python3 web_app.py
```

3. Access dashboard at http://localhost:5001

## How It Works

1. Static Analysis - Scans code for security patterns
2. AI Analysis - Uses Google Gemini for vulnerability detection
3. Risk Assessment - Provides severity levels and mitigation suggestions

## Security Features

- Code execution vulnerability detection
- Tool misuse pattern identification
- File operation security analysis
- Network security concerns
- Prompt injection detection

## Troubleshooting

- Ensure Google API key is set in environment
- Check file permissions and paths
- Verify MCP client configuration
- Restart MCP client after configuration changes

## License

MIT License - see [LICENSE](LICENSE) file for details.
