# main.py - Flask App con Backend Cybersecurity
from flask import Flask, request, jsonify, render_template
from backend_cybersecurity import (
    check_spam_validity, 
    check_breach_status, 
    get_chatbot_response
)
import os
from dotenv import load_dotenv

# Carica variabili d'ambiente
load_dotenv()

app = Flask(__name__)

# --- Rotte del Frontend ---
@app.route('/')
def home():
    """
    Renderizza la pagina HTML principale del frontend.
    Questo sarà il punto di accesso per l'utente.
    """
    return render_template('index.html')

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "message": "Backend Cybersecurity API is running",
        "api_keys_configured": {
            "abstractapi": os.getenv('ABSTRACT_API_KEY') is not None,
            "dehashed": os.getenv('DEHASHED_API_KEY') is not None,
            "anthropic": os.getenv('ANTHROPIC_API_KEY') is not None
        }
    })

# --- Endpoint per la Chatbot ---
@app.route('/ask_chatbot', methods=['POST'])
def ask_chatbot():
    """
    Endpoint API per ricevere le domande della chatbot dal frontend.
    Processa l'input e restituisce la risposta della chatbot con supporto cronologia.
    """
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({"error": "Campo 'message' richiesto"}), 400
        
        user_message = data['message']
        chat_history = data.get('history', [])  # Cronologia opzionale
        
        if not user_message.strip():
            return jsonify({"error": "Messaggio non può essere vuoto"}), 400

        chatbot_response = get_chatbot_response(user_message, chat_history)
        
        return jsonify({
            "success": True,
            "question": user_message,
            "response": chatbot_response
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Errore nel processare la richiesta: {str(e)}"
        }), 500

# --- Endpoint per Solo Controllo Spam ---
@app.route('/check_spam', methods=['POST'])
def check_spam():
    """
    Endpoint per solo controllo spam/validità email.
    Restituisce il formato atteso dall'HTML: valid e spam
    """
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"error": "Campo 'email' richiesto"}), 400
        
        email = data['email'].strip()
        if not email:
            return jsonify({"error": "Email non può essere vuota"}), 400
        
        result = check_spam_validity(email)
        
        # Formato atteso dall'HTML
        formatted_response = {
            "success": True,
            "email": email,
            "valid": result.get('valid', False),
            "spam": not result.get('valid', False) or result.get('fraud_score', 0) > 50,
            "details": {
                "fraud_score": result.get('fraud_score', 0),
                "risk_assessment": result.get('risk_assessment', 'UNKNOWN'),
                "api_source": result.get('api_source', 'Unknown')
            }
        }
        
        return jsonify(formatted_response)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Errore nel controllo spam: {str(e)}"
        }), 500

# --- Endpoint per Solo Controllo Breach ---
@app.route('/check_breach', methods=['POST'])
def check_breach():
    """
    Endpoint per solo controllo breach/compromissione.
    Restituisce il formato atteso dall'HTML: found e breaches
    """
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"error": "Campo 'email' richiesto"}), 400
        
        email = data['email'].strip()
        if not email:
            return jsonify({"error": "Email non può essere vuota"}), 400
        
        result = check_breach_status(email)
        
        # Formato atteso dall'HTML
        formatted_response = {
            "success": True,
            "email": email,
            "found": result.get('breached', False),
            "breaches": [breach.get('name', 'Unknown') for breach in result.get('breaches', [])],
            "details": {
                "breach_count": result.get('breach_count', 0),
                "risk_level": result.get('risk_level', 'LOW'),
                "api_source": result.get('api_source', 'Unknown')
            }
        }
        
        return jsonify(formatted_response)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Errore nel controllo breach: {str(e)}"
        }), 500

if __name__ == '__main__':
    # Esegue l'applicazione Flask
    # Per lo sviluppo, debug=True è utile per ricaricare il server automaticamente.
    app.run(debug=True)