from flask import Flask, request, jsonify, send_from_directory
import os
import json
from datetime import datetime
import threading
import time

app = Flask(__name__, static_folder='dist', static_url_path='')

# Global variables to store scan results and history
latest_results = {}
scan_history = []
scan_counter = 0

def send_results_to_webapp(results):
    """Send scan results to the web application"""
    global latest_results, scan_history, scan_counter
    
    try:
        # Add timestamp and scan ID
        results['timestamp'] = datetime.now().isoformat()
        results['scan_id'] = scan_counter
        scan_counter += 1
        
        # Store as latest results
        latest_results = results
        
        # Add to history
        scan_history.append(results)
        
        # Keep only last 10 scans in history
        if len(scan_history) > 10:
            scan_history.pop(0)
            
        print(f"Results stored in web app")
        
    except Exception as e:
        print(f"⚠️ Error storing results in web app: {e}")

@app.route('/')
def serve_react_app():
    """Serve the React app"""
    return send_from_directory('dist', 'index.html')

@app.route('/api/scan', methods=['POST'])
def receive_scan_results():
    """Receive scan results from MCP server"""
    global latest_results, scan_history, scan_counter
    
    try:
        data = request.get_json()
        
        # Add timestamp and scan ID
        data['timestamp'] = datetime.now().isoformat()
        data['scan_id'] = scan_counter
        scan_counter += 1
        
        # Store as latest results
        latest_results = data
        
        # Add to history
        scan_history.append(data)
        
        # Keep only last 10 scans in history
        if len(scan_history) > 10:
            scan_history.pop(0)
            
        print(f"Received scan results: {data.get('file_path', 'Unknown file')}")
        return jsonify({"status": "success", "message": "Results received"})
        
    except Exception as e:
        print(f"❌ Error receiving scan results: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/results')
def get_latest_results():
    """Get the latest scan results"""
    return jsonify(latest_results)

@app.route('/api/history')
def get_scan_history():
    """Get scan history"""
    return jsonify(scan_history)

@app.route('/api/clear', methods=['GET'])
def clear_results():
    """Clear all results"""
    global latest_results, scan_history
    latest_results = {}
    scan_history = []
    return jsonify({"status": "success", "message": "Results cleared"})

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files for React app or fallback to index.html for React routing"""
    # Check if the path is for a static asset (has a file extension)
    if '.' in path and not path.startswith('api/'):
        try:
            return send_from_directory('dist', path)
        except:
            pass
    
    # For all other routes, serve the React app (index.html)
    # This allows React Router to handle client-side routing
    return send_from_directory('dist', 'index.html')

if __name__ == '__main__':
    # Create dist directory if it doesn't exist
    os.makedirs('dist', exist_ok=True)
    
    print("🚀 Starting MCP Scanner Web App...")
    print("📊 Dashboard will be available at: http://localhost:5001")
    print("📡 API endpoint for results: http://localhost:5001/api/scan")
    
    app.run(debug=False, host='0.0.0.0', port=5001) 