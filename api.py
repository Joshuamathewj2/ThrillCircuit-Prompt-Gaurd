from flask import Flask, request, jsonify
from detector import InjectionDetector
import os

app = Flask(__name__)

# Initialize detector once at startup
# Assuming config is in the same directory or CWD
config_path = os.getenv("DETECTOR_CONFIG", "config.yaml")
detector = InjectionDetector(config_path)

@app.route('/v1/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({"error": "Missing 'prompt' field"}), 400
    
    prompt = data['prompt']
    result = detector.analyze(prompt)
    
    return jsonify(result)

@app.route('/v1/sanitize', methods=['POST'])
def sanitize():
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({"error": "Missing 'prompt' field"}), 400
    
    prompt = data['prompt']
    # Sanitize endpoint just returns the cleaned string for now
    clean_text = detector.sanitizer.clean(prompt)
    
    return jsonify({"original": prompt, "sanitized": clean_text})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "service": "Antigravity Prompt Guard"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
