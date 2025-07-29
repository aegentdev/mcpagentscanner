#!/usr/bin/env python3
"""
Modern Dashboard Runner
Builds the React app and starts both the MCP server and Flask backend
"""

import subprocess
import sys
import os
import time
import signal
import threading
from pathlib import Path

def run_command(command, description, background=False):
    """Run a command and handle output"""
    print(f"🚀 {description}...")
    
    if background:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Print output in real-time
        def print_output():
            for line in process.stdout:
                print(f"[{description}] {line.strip()}")
        
        output_thread = threading.Thread(target=print_output)
        output_thread.daemon = True
        output_thread.start()
        
        return process
    else:
        try:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            print(f"✅ {description} completed successfully")
            return result
        except subprocess.CalledProcessError as e:
            print(f"❌ {description} failed: {e}")
            print(f"Error output: {e.stderr}")
            return None

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    # Check if Node.js is installed
    node_result = subprocess.run("node --version", shell=True, capture_output=True)
    if node_result.returncode != 0:
        print("❌ Node.js is not installed. Please install Node.js first.")
        return False
    
    # Check if npm is installed
    npm_result = subprocess.run("npm --version", shell=True, capture_output=True)
    if npm_result.returncode != 0:
        print("❌ npm is not installed. Please install npm first.")
        return False
    
    print("✅ Dependencies check passed")
    return True

def install_npm_dependencies():
    """Install npm dependencies"""
    print("📦 Installing npm dependencies...")
    result = run_command("npm install", "Installing npm dependencies")
    return result is not None

def build_react_app():
    """Build the React app"""
    print("🔨 Building React app...")
    result = run_command("npm run build", "Building React app")
    return result is not None

def main():
    """Main function to run the modern dashboard"""
    print("🎯 Starting Modern MCP Scanner Dashboard")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Install npm dependencies
    if not install_npm_dependencies():
        print("❌ Failed to install npm dependencies")
        sys.exit(1)
    
    # Build React app
    if not build_react_app():
        print("❌ Failed to build React app")
        sys.exit(1)
    
    # Start Flask backend
    print("🌐 Starting Flask backend...")
    flask_process = run_command("python3 app.py", "Flask Backend", background=True)
    
    if not flask_process:
        print("❌ Failed to start Flask backend")
        sys.exit(1)
    
    # Wait a moment for Flask to start
    time.sleep(3)
    
    # Start MCP server
    print("🤖 Starting MCP server...")
    mcp_process = run_command("python3 server.py", "MCP Server", background=True)
    
    if not mcp_process:
        print("❌ Failed to start MCP server")
        flask_process.terminate()
        sys.exit(1)
    
    print("\n" + "=" * 50)
    print("🎉 Modern Dashboard is running!")
    print("📊 Dashboard: http://localhost:5001")
    print("📡 API: http://localhost:5001/api/scan")
    print("🤖 MCP Server: Running on stdio")
    print("\n💡 To test the MCP server, use:")
    print("   autoharden_agent /path/to/your/agent/file.py")
    print("\n🛑 Press Ctrl+C to stop all services")
    print("=" * 50)
    
    try:
        # Keep the script running
        while True:
            time.sleep(1)
            
            # Check if processes are still running
            if flask_process.poll() is not None:
                print("❌ Flask backend stopped unexpectedly")
                break
                
            if mcp_process.poll() is not None:
                print("❌ MCP server stopped unexpectedly")
                break
                
    except KeyboardInterrupt:
        print("\n🛑 Shutting down services...")
        
        # Terminate processes
        if flask_process:
            flask_process.terminate()
            print("✅ Flask backend stopped")
            
        if mcp_process:
            mcp_process.terminate()
            print("✅ MCP server stopped")
            
        print("👋 Goodbye!")

if __name__ == "__main__":
    main() 