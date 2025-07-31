# MCP Agent Scanner - AutoHardener

AI Agent Security Hardening Tool using Model Context Protocol (MCP).

## Features

- Static security analysis of Python code
- AI-powered vulnerability detection using Google Gemini
- Risk categorization (Critical, Medium, Low)
- Modern React web dashboard for viewing scan results
- Real-time scan monitoring and history
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

Configure your MCP client (Gemini, Cursor, etc.) to connect to the server:

### Gemini Desktop
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
- `ping_pong(random_string: str)` - Health check

### Running the Modern Frontend

#### Option 1: Development Mode (Recommended)
```bash
# Terminal 1: Start React development server
npm run dev

# Terminal 2: Start Flask backend (optional - for API endpoints)
python app.py
```

Access the dashboard at http://localhost:3000

#### Option 2: Production Build
```bash
# Build the React app
npm run build

# Start Flask backend (serves the built React app)
python app.py
```

Access the dashboard at http://localhost:5000

#### Option 3: All-in-One Script
```bash
# Builds React app and starts both frontend and backend
python run_modern_dashboard.py
```

### Frontend Features

- **Real-time Dashboard**: Live monitoring of scan results
- **Scan History**: View previous scans and their results
- **Risk Analysis**: Detailed breakdown of security risks
- **Modern UI**: Built with React, TypeScript, and Tailwind CSS
- **Responsive Design**: Works on desktop and mobile devices

## How It Works

1. **Static Analysis** - Scans code for security patterns
2. **AI Analysis** - Uses Google Gemini for vulnerability detection
3. **Risk Assessment** - Provides severity levels and mitigation suggestions
4. **Real-time Updates** - Frontend automatically refreshes with new scan results

## Security Features

- Code execution vulnerability detection
- Tool misuse pattern identification
- File operation security analysis
- Network security concerns
- Prompt injection detection

## Project Structure

```
mcpagentscanner/
├── src/                    # React frontend source
│   ├── components/         # React components
│   ├── pages/             # Page components
│   └── lib/               # Utility functions
├── server.py              # MCP server
├── app.py                 # Flask backend API
├── run_modern_dashboard.py # All-in-one runner
└── package.json           # Node.js dependencies
```

## Troubleshooting

- Ensure Google API key is set in environment
- Check file permissions and paths
- Verify MCP client configuration
- Restart MCP client after configuration changes
- If frontend doesn't load, try `npm install` to ensure dependencies are installed



## License

MIT License - see [LICENSE](LICENSE) file for details.
