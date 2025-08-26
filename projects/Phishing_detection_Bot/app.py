from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
from phishguard_ai import PhishingDetectionChatbot

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

chatbot = None

def initialize_chatbot():
    global chatbot
    if chatbot is None:
        try:
            chatbot = PhishingDetectionChatbot()
            # Force model initialization
            if hasattr(chatbot, 'initialize_model'):
                chatbot.initialize_model()
        except Exception as e:
            print(f"Warning: Could not initialize ML model: {str(e)}")
            # Continue with rule-based analysis only
            pass

@app.route('/')
def index():
    initialize_chatbot()
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    initialize_chatbot()
    data = request.get_json()
    content = data.get('content', '')
    analysis_type = data.get('type', 'url')
    
    if not content:
        return jsonify({'error': 'No content provided'}), 400
    
    try:
        if analysis_type == 'url':
            # Analyze URL for phishing indicators
            risk_score, reason = chatbot.analyze_url_internal(content)
            risk_level = "High" if risk_score >= 60 else "Medium" if risk_score >= 30 else "Low" if risk_score > 0 else "Minimal"
            
            # Format result for frontend
            result = {
                'title': f'URL Analysis: {risk_level} Risk',
                'message': f'Risk Score: {risk_score}/100',
                'details': reason,
                'type': 'success' if risk_level == 'Minimal' else 'warning' if risk_level in ['Low', 'Medium'] else 'danger',
                'risk_score': risk_score,
                'risk_level': risk_level,
                'reason': reason
            }
        elif analysis_type == 'message':
            # Analyze message for phishing indicators
            analysis = chatbot.analyze_text_for_phishing(content)
            
            # Calculate risk level based on risk score
            risk_score = analysis.get('risk_score', 0)
            risk_level = "High" if risk_score >= 60 else "Medium" if risk_score >= 30 else "Low" if risk_score > 0 else "Minimal"
            
            # Format result for frontend
            result = {
                'title': f'Message Analysis: {risk_level} Risk',
                'message': f'Risk Score: {risk_score}/100',
                'details': {
                    'text_score': analysis.get('text_score', 0),
                    'url_score': analysis.get('url_score', 0),
                    'patterns': analysis.get('risk_factors', []),
                    'suspicious_urls': analysis.get('suspicious_urls', [])
                },
                'type': 'success' if risk_level == 'Minimal' else 'warning' if risk_level in ['Low', 'Medium'] else 'danger',
                'risk_score': risk_score,
                'risk_level': risk_level
            }
        else:
            return jsonify({'error': 'Invalid analysis type'}), 400
            
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    initialize_chatbot()
    data = request.get_json()
    message = data.get('message', '')
    
    if not message:
        return jsonify({'error': 'No message provided'}), 400
    
    try:
        response = chatbot.get_response(message)
        return jsonify({'response': response})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/feedback', methods=['POST'])
def feedback():
    initialize_chatbot()
    data = request.get_json()
    
    analysis_type = data.get('type')
    content = data.get('content')
    user_feedback = data.get('feedback')
    original_risk_score = data.get('original_risk_score')
    
    if not all([analysis_type, content, user_feedback, original_risk_score]):
        return jsonify({'error': 'Missing required feedback data'}), 400
    
    try:
        result = chatbot.process_feedback(
            analysis_type,
            content,
            user_feedback,
            original_risk_score
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Failed to process feedback: {str(e)}'}), 500

@app.route('/api/learning/stats', methods=['GET'])
def learning_stats():
    initialize_chatbot()
    try:
        stats = chatbot.get_learning_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': f'Failed to get learning stats: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000) 