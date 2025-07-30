# 🔐 VerificaMASSI - Cybersecurity Email Analysis

> **Piattaforma professionale per l'analisi di sicurezza email con integrazione AI**

Un backend Python completo per la verifica e analisi di sicurezza delle email, integrato con le API più avanzate del settore e un chatbot AI intelligente.

## 🚀 **Caratteristiche Principali**

### ✅ **Email Validation & Analysis**
- **Abstract API Integration**: Validazione email professionale con quality score
- **Controllo formato e sintassi** avanzato con regex ottimizzate
- **Analisi deliverability** e reputation del dominio
- **Detection email disposabili** e temporanee
- **Controllo MX records** e validazione SMTP

### 🛡️ **Breach Detection**
- **DeHashed API Integration**: Database completo di data breach
- **Ricerca compromissioni** in oltre 12 miliardi di record
- **Analisi password compromesse** e dati sensibili esposti
- **Risk assessment** automatico basato sui breach trovati
- **Raccomandazioni di sicurezza** personalizzate

### 🤖 **AI-Powered Chatbot**
- **Anthropic Claude Integration**: Chatbot avanzato per consulenza cybersecurity
- **Risposte intelligenti** su temi di sicurezza informatica
- **Analisi contextual** delle minacce email
- **Consigli personalizzati** basati sui risultati delle analisi

### 🌐 **Web Interface**
- **Dashboard responsiva** per testing e monitoring
- **Real-time API testing** con interfaccia moderna
- **Visualizzazione risultati** con grafici e metriche
- **Export dei report** in formato JSON

## 📁 **Struttura del Progetto**

```
VerificaMASSI/
├── 📄 backend_cybersecurity.py    # Core backend engine
├── 🌐 main.py                     # Flask web application
├── 📋 requirements.txt            # Python dependencies
├── 🔑 .env                        # API keys (configurate)
├── 📝 .env.example               # Template per sviluppatori
├── 📖 README.md                  # Documentazione completa
├── 🎨 templates/
│   └── index.html                # Web interface
├── 🔧 .venv/                     # Virtual environment
└── 📁 .git/                     # Repository Git
```

## ⚙️ **Configurazione API**

### 🔑 **API Keys Necessarie**

1. **Abstract API** (Email Validation) - ✅ **CONFIGURATA**
   - Registrazione: https://app.abstractapi.com/api/email-validation
   - Quality Score: 0.99 per email verificate
   - Rate limit: 1 req/sec (piano gratuito)

2. **DeHashed API** (Breach Detection) - ✅ **CONFIGURATA**  
   - Registrazione: https://www.dehashed.com/
   - Database: 12+ miliardi di record compromessi
   - Ricerca avanzata per email, username, password

3. **Anthropic Claude** (AI Chatbot) - ✅ **CONFIGURATA**
   - Registrazione: https://console.anthropic.com/
   - Modello: Claude-3.5 Sonnet
   - Specializzato in cybersecurity consulting

## 🚀 **Installazione e Setup**

### 1️⃣ **Clone del Repository**
```bash
git clone https://github.com/Walterprop/VerificaMASSI.git
cd VerificaMASSI
```

### 2️⃣ **Setup Virtual Environment**
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac
```

### 3️⃣ **Installazione Dipendenze**
```bash
pip install -r requirements.txt
```

### 4️⃣ **Configurazione API Keys**
```bash
# Copia il template delle variabili d'ambiente
cp .env.example .env

# Modifica .env con le tue API keys
ABSTRACT_API_KEY=your_abstract_api_key_here
DEHASHED_API_KEY=your_dehashed_api_key_here  
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

### 5️⃣ **Avvio dell'Applicazione**
```bash
python main.py
```

L'applicazione sarà disponibile su: **http://localhost:5000**

## 🔧 **Utilizzo delle API**

### 📧 **Email Validation**
```python
from backend_cybersecurity import EmailValidator

validator = EmailValidator()
result = validator.check_spam_validity("test@example.com")

print(f"Valid: {result['valid']}")
print(f"Quality Score: {result['abstract_data']['quality_score']}")
print(f"Risk Level: {result['risk_assessment']}")
```

### 🛡️ **Breach Detection**
```python
breach_result = validator.check_breach_status("test@example.com")

print(f"Breached: {breach_result['breached']}")
print(f"Databases Found: {len(breach_result['databases_found'])}")
print(f"Risk Level: {breach_result['risk_level']}")
```

### 🤖 **AI Chatbot**
```python
from backend_cybersecurity import CybersecurityChatbot

chatbot = CybersecurityChatbot()
response = chatbot.get_chatbot_response("Come posso proteggere la mia email?")

print(f"AI Response: {response['response']}")
```

## 🌐 **API Endpoints**

| Endpoint | Metodo | Descrizione |
|----------|--------|-------------|
| `/` | GET | Web interface dashboard |
| `/health` | GET | Status dell'applicazione |
| `/check_email` | POST | Analisi completa email |
| `/check_spam` | POST | Solo validazione email |
| `/check_breach` | POST | Solo controllo breach |
| `/ask_chatbot` | POST | Query al chatbot AI |

### 📝 **Esempio Request**
```json
POST /check_email
Content-Type: application/json

{
  "email": "test@example.com"
}
```

### 📊 **Esempio Response**
```json
{
  "success": true,
  "email": "test@example.com",
  "spam_results": {
    "valid": true,
    "quality_score": 0.99,
    "risk_assessment": "LOW",
    "api_source": "Abstract API"
  },
  "breach_results": {
    "breached": false,
    "breach_count": 0,
    "risk_level": "LOW",
    "api_source": "DeHashed"
  },
  "overall_risk": "LOW",
  "timestamp": "2025-07-30T10:30:00"
}
```

## 🔒 **Sicurezza e Privacy**

- ✅ **API Keys protette** con variabili d'ambiente
- ✅ **Logging sicuro** senza esposizione dati sensibili  
- ✅ **Rate limiting** automatico per proteggere le API
- ✅ **Fallback intelligenti** quando le API non sono disponibili
- ✅ **Validazione input** robusta per prevenire injection

## 🚦 **Error Handling**

Il sistema include gestione completa degli errori:

- **API Failures**: Fallback automatico con risultati simulati
- **Rate Limiting**: Gestione intelligente dei limiti API
- **Network Issues**: Retry automatici e timeout configurabili
- **Invalid Input**: Validazione e sanitizzazione completa

## 📈 **Performance**

- **Response Time**: < 2 secondi per analisi completa
- **Concurrent Users**: Supporto multi-threading
- **Scalability**: Architettura modulare per deploy enterprise
- **Caching**: Risultati cachati per ottimizzare performance

## 🤝 **Contributi**

1. Fork del repository
2. Crea un feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit delle modifiche (`git commit -m 'Add AmazingFeature'`)
4. Push del branch (`git push origin feature/AmazingFeature`)
5. Apri una Pull Request

## 📝 **Licenza**

Distribuito sotto licenza MIT. Vedi `LICENSE` per maggiori informazioni.

## 👨‍💻 **Autore**

**Walter Cavaliere** - [@Walterprop](https://github.com/Walterprop)

- 📧 Email: walter.cavaliere@edu-its.it
- 🔗 GitHub: https://github.com/Walterprop/VerificaMASSI

---

⭐ **Se questo progetto ti è stato utile, lascia una stella su GitHub!**
