#!/usr/bin/env python3
from flask import Flask, jsonify, render_template
import subprocess
import json

app = Flask(__name__, template_folder='.')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/ports')
def api_ports():
    try:
        result = subprocess.run(['vigil-scan', '--json', '--scan-ports'], 
                              capture_output=True, text=True, timeout=10)
        return jsonify(json.loads(result.stdout))
    except:
        return jsonify(["API not ready"])

@app.route('/api/processes')
def api_processes():
    try:
        result = subprocess.run(['vigil-scan', '--json', '--scan-processes'], 
                              capture_output=True, text=True, timeout=10)
        return jsonify(json.loads(result.stdout))
    except:
        return jsonify(["Monitoring inactive"])

@app.route('/api/secrets')
def api_secrets():
    try:
        result = subprocess.run(['vigil-scan', '--json', '--scan-secrets'], 
                              capture_output=True, text=True, timeout=10)
        return jsonify(json.loads(result.stdout))
    except:
        return jsonify(["Scanner not initialized"])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
