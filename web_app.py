from flask import Flask, render_template, request, jsonify, redirect, url_for
import json
import os
from datetime import datetime
import threading
import time

app = Flask(__name__)

# Global variable to store the latest scan results
latest_results = None
scan_history = []

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html', 
                         latest_results=latest_results,
                         scan_history=scan_history)

@app.route('/api/scan', methods=['POST'])
def receive_scan_results():
    """API endpoint to receive scan results from MCP scanner"""
    global latest_results
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data received"}), 400
        
        # Add timestamp
        data['timestamp'] = datetime.now().isoformat()
        data['id'] = len(scan_history) + 1
        
        # Store as latest results
        latest_results = data
        
        # Add to history (keep last 10 scans)
        scan_history.append(data)
        if len(scan_history) > 10:
            scan_history.pop(0)
        
        print(f"✅ Received scan results for: {data.get('file_path', 'Unknown')}")
        return jsonify({"success": True, "message": "Results received"})
        
    except Exception as e:
        print(f"❌ Error receiving scan results: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/results')
def get_results():
    """API endpoint to get latest results"""
    return jsonify(latest_results if latest_results else {})

@app.route('/api/history')
def get_history():
    """API endpoint to get scan history"""
    return jsonify(scan_history)

@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    """View specific scan results"""
    scan = next((s for s in scan_history if s.get('id') == scan_id), None)
    if not scan:
        return redirect(url_for('index'))
    return render_template('scan_detail.html', scan=scan)

@app.route('/api/clear')
def clear_results():
    """Clear all results"""
    global latest_results, scan_history
    latest_results = None
    scan_history = []
    return jsonify({"success": True, "message": "Results cleared"})

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    print("🚀 Starting MCP Scanner Web App...")
    print("📊 Dashboard will be available at: http://localhost:5000")
    print("📡 API endpoint for results: http://localhost:5000/api/scan")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 