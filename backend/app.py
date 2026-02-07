from flask import Flask, request, jsonify, send_from_directory
import os
import sys

# Ensure backend directory is in path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.url_parser import URLParser
from core.rule_engine import RuleEngine
from core.scoring import Scorer
from core.verdict import VerdictSystem
from utils.validators import validate_url

# Setup paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='/')

# Initialize Core Components
rule_engine = RuleEngine()
scorer = Scorer()
verdict_system = VerdictSystem()

@app.route('/')
def home():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(FRONTEND_DIR, path)

@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400
    
    url = data['url']
    
    # 1. Validation
    if not validate_url(url):
        return jsonify({
            "error": "Invalid URL format", 
            "verdict": "INVALID",
            "score": 0,
            "triggered_rules": []
        }), 400

    try:
        # 2. Parsing
        parser = URLParser(url)
        
        # 3. Rule Execution
        triggered = rule_engine.run_rules(parser)
        
        # 4. Scoring
        total_score = scorer.calculate_total_score(triggered)
        
        # 5. Verdict
        final_verdict = verdict_system.get_verdict(total_score)
        
        response = {
            "url": url,
            "verdict": final_verdict,
            "score": total_score,
            "triggered_rules": triggered,
            "components": parser.get_components() # Helpful for debugging/UI
        }
        
        return jsonify(response)

    except Exception as e:
        print(f"Error processing URL: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
