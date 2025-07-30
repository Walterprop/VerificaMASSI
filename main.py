# main.py - Flask App con Backend Cybersecurity
from flask import Flask, request, jsonify, render_template
from backend_cybersecurity import (
    analyze_email, 
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
    Processa l'input e restituisce la risposta della chatbot.
    """
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({"error": "Campo 'message' richiesto"}), 400
        
        user_message = data['message']
        if not user_message.strip():
            return jsonify({"error": "Messaggio non può essere vuoto"}), 400

        chatbot_response = get_chatbot_response(user_message)
        
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

# --- Endpoint per Analisi Email Completa ---
@app.route('/check_email', methods=['POST'])
def check_email():
    """
    Endpoint per l'analisi completa email (spam + breach).
    """
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"error": "Campo 'email' richiesto"}), 400
        
        email = data['email'].strip()
        if not email:
            return jsonify({"error": "Email non può essere vuota"}), 400
        
        # Analisi completa
        result = analyze_email(email)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Errore nell'analisi email: {str(e)}"
        }), 500

# --- Endpoint per Solo Controllo Spam ---
@app.route('/check_spam', methods=['POST'])
def check_spam():
    """
    Endpoint per solo controllo spam/validità email.
    """
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"error": "Campo 'email' richiesto"}), 400
        
        email = data['email'].strip()
        if not email:
            return jsonify({"error": "Email non può essere vuota"}), 400
        
        result = check_spam_validity(email)
        
        return jsonify(result)
        
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
    """
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"error": "Campo 'email' richiesto"}), 400
        
        email = data['email'].strip()
        if not email:
            return jsonify({"error": "Email non può essere vuota"}), 400
        
        result = check_breach_status(email)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Errore nel controllo breach: {str(e)}"
        }), 500

if __name__ == '__main__':
    # Esegue l'applicazione Flask
    # Per lo sviluppo, debug=True è utile per ricaricare il server automaticamente.
    app.run(debug=True)