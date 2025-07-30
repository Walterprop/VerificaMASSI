# main.py
from flask import Flask, request, jsonify, render_template
from chatbot_core import get_chatbot_response

app = Flask(__name__)

# --- Rotte del Frontend ---
@app.route('/')
def home():
    """
    Renderizza la pagina HTML principale del frontend.
    Questo sarà il punto di accesso per l'utente.
    """
    return render_template('index.html') # Assumi che avrai un file index.html nella cartella 'templates'

# --- Endpoint per la Chatbot (Parte 1) ---
@app.route('/ask_chatbot', methods=['POST'])
def ask_chatbot():
    """
    Endpoint API per ricevere le domande della chatbot dal frontend.
    Processa l'input e restituisce la risposta della chatbot.
    """
    user_message = request.json.get('message')
    if not user_message:
        return jsonify({"response": "Per favore, inserisci un messaggio."}), 400

    chatbot_response = get_chatbot_response(user_message)
    
    return jsonify({"response": chatbot_response})

# --- Segnaposto per la Parte 2: Endpoint API esterne (da implementare) ---
@app.route('/check_email', methods=['POST'])
def check_email():
    """
    Endpoint per il controllo email spam/breach.
    Questo verrà implementato nella Parte 2.
    """
    email = request.json.get('email')
    if not email:
        return jsonify({"error": "Indirizzo email non fornito."}), 400
    
    # Logica per chiamare le API esterne (Spamhaus, Have I Been Pwned) andrà qui.
    # Per ora, restituisce un messaggio di segnaposto.
    return jsonify({
        "email": email,
        "spam_check": "Funzionalità di controllo spam da implementare.",
        "breach_check": "Funzionalità di verifica breach da implementare."
    })

if __name__ == '__main__':
    # Esegue l'applicazione Flask
    # Per lo sviluppo, debug=True è utile per ricaricare il server automaticamente.
    app.run(debug=True)