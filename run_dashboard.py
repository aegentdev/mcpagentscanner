#!/usr/bin/env python3
"""
MCP Agent Scanner Dashboard Runner

This script runs both the MCP server and web dashboard together.
"""

import subprocess
import sys
import time
import os
import signal
import threading
from pathlib import Path

def run_command(command, name, cwd=None):
    """Run a command in a subprocess"""
    print(f"🚀 Starting {name}...")
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Print output in real-time
        for line in process.stdout:
            print(f"[{name}] {line.rstrip()}")
            
        return process
    except Exception as e:
        print(f"❌ Failed to start {name}: {e}")
        return None

def main():
    print("🔒 MCP Agent Scanner Dashboard")
    print("=" * 50)
    
    # Check if required files exist
    if not Path("server.py").exists():
        print("❌ server.py not found!")
        return 1
    
    if not Path("app.py").exists():
        print("❌ app.py not found!")
        return 1
    
    # Check if .env file exists
    if not Path(".env").exists():
        print("⚠️  .env file not found. Please create one with your GOOGLE_API_KEY")
        print("Example:")
        print("GOOGLE_API_KEY=your_api_key_here")
        print()
    
    print("📋 Starting services...")
    print("   - MCP Server (for agent scanning)")
    print("   - Web Dashboard (for viewing results)")
    print()
    
    # Start web app in background
    web_process = run_command("python3 app.py", "Web Dashboard")
    if not web_process:
        return 1
    
    # Wait a moment for web app to start
    time.sleep(3)
    
    # Start MCP server
    mcp_process = run_command("python3 server.py", "MCP Server")
    if not mcp_process:
        web_process.terminate()
        return 1
    
    print()
    print("✅ Both services are running!")
    print("📊 Web Dashboard: http://localhost:5001")
    print("🔧 MCP Server: Ready for connections")
    print()
    print("Press Ctrl+C to stop both services")
    
    try:
        # Wait for processes
        while True:
            if web_process.poll() is not None:
                print("❌ Web Dashboard stopped unexpectedly")
                break
            if mcp_process.poll() is not None:
                print("❌ MCP Server stopped unexpectedly")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping services...")
        
        # Terminate processes
        if web_process:
            web_process.terminate()
        if mcp_process:
            mcp_process.terminate()
        
        # Wait for them to stop
        if web_process:
            web_process.wait()
        if mcp_process:
            mcp_process.wait()
        
        print("✅ Services stopped")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 