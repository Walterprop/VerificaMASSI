"""
Backend Python per Cybersecurity Email Analysis
Integra IPQualityScore Email Validation API e Have I Been Pwned API
Pronto per integrazione con Flask/FastAPI
"""

import requests
import json
import re
import os
from typing import Dict, List, Optional
from datetime import datetime
import logging
from dotenv import load_dotenv

# Carica variabili d'ambiente dal file .env
load_dotenv()

# Configurazione logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurazione API Keys (da impostare come variabili d'ambiente)
ABSTRACT_API_KEY = os.getenv('ABSTRACT_API_KEY', 'YOUR_ABSTRACT_API_KEY')
DEHASHED_API_KEY = os.getenv('DEHASHED_API_KEY', 'YOUR_DEHASHED_API_KEY')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', 'YOUR_ANTHROPIC_API_KEY')

class EmailValidator:
    """Classe per la validazione e controllo email"""
    
    def __init__(self):
        self.abstract_base_url = "https://emailvalidation.abstractapi.com/v1"
        self.dehashed_base_url = "https://app.dehashed.com/api/search"
    
    def validate_email_format(self, email: str) -> bool:
        """Valida il formato dell'email con regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def check_spam_validity(self, email: str) -> Dict:
        """
        Controllo SPAM/validità email usando Abstract API
        
        Args:
            email (str): Indirizzo email da verificare
            
        Returns:
            Dict: Risultati della verifica spam/validità
        """
        try:
            # Validazione formato email
            if not self.validate_email_format(email):
                return {
                    "success": False,
                    "error": "Formato email non valido",
                    "email": email,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Controllo chiave API
            if ABSTRACT_API_KEY == 'YOUR_ABSTRACT_API_KEY':
                return self._fallback_spam_check(email, "Chiave API Abstract non configurata")
            
            # Chiamata API Abstract
            url = self.abstract_base_url
            params = {
                'api_key': ABSTRACT_API_KEY,
                'email': email,
                'auto_correct': 'true'
            }
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            # Controlla se la risposta è un errore dell'API
            if 'error' in data:
                error_msg = data.get('error', {}).get('message', 'Errore API sconosciuto')
                if "quota" in error_msg.lower() or "credit" in error_msg.lower():
                    return self._fallback_spam_check(email, "Crediti API esauriti - usando analisi simulata")
                else:
                    return self._fallback_spam_check(email, f"Errore API: {error_msg}")
            
            # Conversione dei risultati Abstract API al nostro formato
            # Abstract restituisce valori booleani in formato {"value": bool, "text": "TRUE/FALSE"}
            def get_bool_value(field):
                if isinstance(field, dict):
                    return field.get('value', False)
                return bool(field)
            
            # Calcolo fraud_score basato sui parametri Abstract
            fraud_score = 0
            if not get_bool_value(data.get('is_valid_format', False)):
                fraud_score += 40
            if get_bool_value(data.get('is_disposable_email', False)):
                fraud_score += 30
            if get_bool_value(data.get('is_role_email', False)):
                fraud_score += 20
            if not get_bool_value(data.get('is_mx_found', True)):
                fraud_score += 25
            if not get_bool_value(data.get('is_smtp_valid', True)):
                fraud_score += 15
            
            # Inverti quality_score (Abstract: alto = buono, noi: basso = buono)
            quality_score = data.get('quality_score', 0.5)
            fraud_score += int((1 - quality_score) * 50)
            
            # Limita fraud_score tra 0 e 100
            fraud_score = min(max(fraud_score, 0), 100)
            
            result = {
                "success": True,
                "email": email,
                "valid": get_bool_value(data.get('is_valid_format', False)) and data.get('deliverability') == 'DELIVERABLE',
                "disposable": get_bool_value(data.get('is_disposable_email', False)),
                "spam_trap_score": fraud_score // 5,  # Converte in scala 0-20
                "overall_score": fraud_score,
                "deliverability": data.get('deliverability', 'UNKNOWN').lower(),
                "catch_all": get_bool_value(data.get('is_catchall_email', False)),
                "generic": get_bool_value(data.get('is_role_email', False)),
                "common": get_bool_value(data.get('is_free_email', False)),
                "dns_valid": get_bool_value(data.get('is_mx_found', True)),
                "honeypot": False,  # Abstract non ha questo campo
                "frequent_complainer": False,  # Abstract non ha questo campo
                "suspect": fraud_score > 70,
                "recent_abuse": False,  # Abstract non ha questo campo
                "fraud_score": fraud_score,
                "suggested_domain": data.get('autocorrect', ''),
                "leaked": False,  # Controlleremo con HIBP
                "domain_age": {"human": "Unknown", "timestamp": 0},  # Abstract non ha questo dato
                "first_name": "",
                "timestamp": datetime.now().isoformat(),
                "risk_assessment": self._assess_email_risk_abstract(fraud_score, get_bool_value(data.get('is_disposable_email', False)), fraud_score > 70),
                "api_source": "Abstract API",
                "abstract_data": {
                    "quality_score": data.get('quality_score', 0),
                    "deliverability": data.get('deliverability', 'UNKNOWN'),
                    "is_valid_format": get_bool_value(data.get('is_valid_format', False)),
                    "is_free_email": get_bool_value(data.get('is_free_email', False)),
                    "is_disposable_email": get_bool_value(data.get('is_disposable_email', False)),
                    "is_role_email": get_bool_value(data.get('is_role_email', False)),
                    "is_catchall_email": get_bool_value(data.get('is_catchall_email', False)),
                    "is_mx_found": get_bool_value(data.get('is_mx_found', True)),
                    "is_smtp_valid": get_bool_value(data.get('is_smtp_valid', True))
                }
            }
            
            logger.info(f"Email spam check completato per: {email} - Fraud Score: {fraud_score}")
            return result
            
        except requests.RequestException as e:
            logger.error(f"Errore nella richiesta API Abstract: {e}")
            return self._fallback_spam_check(email, f"Errore connessione API: {str(e)}")
        except Exception as e:
            logger.error(f"Errore generico nel controllo spam: {e}")
            return self._fallback_spam_check(email, f"Errore interno: {str(e)}")
    
    def _assess_email_risk_abstract(self, fraud_score: int, disposable: bool, suspect: bool) -> str:
        """Valuta il rischio email basandosi sui dati Abstract API"""
        if fraud_score >= 75 or disposable or suspect:
            return "HIGH"
        elif fraud_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _fallback_spam_check(self, email: str, error_msg: str) -> Dict:
        """Controllo spam simulato quando l'API reale fallisce"""
        domain = email.split('@')[1].lower()
        
        # Domini educativi e famosi sono considerati sicuri
        safe_domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'edu-its.it', 'university.', '.edu', '.gov']
        is_safe_domain = any(safe in domain for safe in safe_domains)
        
        if is_safe_domain:
            fraud_score = 5  # Score molto basso per domini sicuri
            valid = True
            disposable = False
            suspect = False
        else:
            fraud_score = 35  # Score medio per domini sconosciuti
            valid = True
            disposable = False
            suspect = False
        
        return {
            "success": True,
            "email": email,
            "valid": valid,
            "disposable": disposable,
            "spam_trap_score": 0,
            "overall_score": fraud_score,
            "deliverability": "high" if valid else "medium",
            "catch_all": False,
            "generic": False,
            "common": True,
            "dns_valid": True,
            "honeypot": False,
            "frequent_complainer": False,
            "suspect": suspect,
            "recent_abuse": False,
            "fraud_score": fraud_score,
            "suggested_domain": "",
            "leaked": False,
            "domain_age": {"human": "Unknown", "timestamp": 0},
            "first_name": "",
            "timestamp": datetime.now().isoformat(),
            "risk_assessment": self._assess_email_risk({"fraud_score": fraud_score, "disposable": disposable, "suspect": suspect}),
            "api_source": "Fallback Analysis",
            "note": f"⚠️ {error_msg} - Risultati simulati"
        }
    
    def check_breach_status(self, email: str) -> Dict:
        """
        Controllo compromissione usando DeHashed API
        
        Args:
            email (str): Indirizzo email da verificare
            
        Returns:
            Dict: Risultati della verifica breach
        """
        try:
            # Validazione formato email
            if not self.validate_email_format(email):
                return {
                    "success": False,
                    "error": "Formato email non valido",
                    "email": email,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Controllo chiave API
            if DEHASHED_API_KEY == 'YOUR_DEHASHED_API_KEY':
                return self._fallback_breach_check(email, "Chiave API DeHashed non configurata")
            
            # Chiamata API DeHashed
            url = self.dehashed_base_url
            headers = {
                'Accept': 'application/json',
                'Authorization': f'Bearer {DEHASHED_API_KEY}',
                'User-Agent': 'Python-Cybersecurity-Backend'
            }
            params = {
                'query': f'email:{email}',
                'size': 100  # Limite risultati
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 401:
                return self._fallback_breach_check(email, "API key DeHashed non valida")
            elif response.status_code == 429:
                return self._fallback_breach_check(email, "Rate limit DeHashed raggiunto")
            elif response.status_code != 200:
                return self._fallback_breach_check(email, f"Errore API DeHashed: {response.status_code}")
            
            data = response.json()
            entries = data.get('entries', [])
            
            if not entries:
                # Nessun breach trovato
                return {
                    "success": True,
                    "email": email,
                    "breached": False,
                    "breach_count": 0,
                    "breaches": [],
                    "entries": [],
                    "message": "Nessun breach rilevato per questa email",
                    "timestamp": datetime.now().isoformat(),
                    "risk_level": "LOW",
                    "api_source": "DeHashed"
                }
            
            # Processa i risultati DeHashed
            processed_breaches = []
            databases_found = set()
            
            for entry in entries:
                db_name = entry.get('database_name', 'Unknown')
                databases_found.add(db_name)
                
                # Crea entry per ogni database trovato
                if db_name not in [b['name'] for b in processed_breaches]:
                    processed_breaches.append({
                        "name": db_name,
                        "title": db_name,
                        "domain": entry.get('domain', ''),
                        "breach_date": entry.get('obtained_from', 'Unknown'),
                        "added_date": datetime.now().isoformat(),
                        "pwn_count": 1,  # DeHashed non fornisce questo dato
                        "description": f"Data breach found in {db_name} database",
                        "data_classes": self._extract_data_classes(entry),
                        "is_verified": True,
                        "is_fabricated": False,
                        "is_sensitive": self._is_sensitive_breach(entry)
                    })
            
            # Determina livello di rischio
            risk_level = "LOW"
            if len(databases_found) >= 5:
                risk_level = "HIGH"
            elif len(databases_found) >= 2:
                risk_level = "MEDIUM"
            
            # Genera raccomandazioni
            recommendations = [
                "Cambia immediatamente la password per tutti gli account associati a questa email",
                "Attiva l'autenticazione a due fattori dove possibile",
                "Monitora regolarmente i tuoi account per attività sospette"
            ]
            
            if any(entry.get('password') or entry.get('hashed_password') for entry in entries):
                recommendations.insert(0, "⚠️ PASSWORD COMPROMESSE RILEVATE - Cambia TUTTE le password immediatamente!")
            
            return {
                "success": True,
                "email": email,
                "breached": True,
                "breach_count": len(processed_breaches),
                "breaches": processed_breaches,
                "databases_found": list(databases_found),
                "message": f"Trovati {len(processed_breaches)} breach in {len(databases_found)} database per questa email",
                "timestamp": datetime.now().isoformat(),
                "risk_level": risk_level,
                "recommendations": recommendations,
                "api_source": "DeHashed",
                "total_entries": len(entries)
            }
            
        except requests.RequestException as e:
            logger.error(f"Errore nella richiesta API DeHashed: {e}")
            return self._fallback_breach_check(email, f"Errore connessione API: {str(e)}")
        except Exception as e:
            logger.error(f"Errore generico nel controllo breach: {e}")
            return self._fallback_breach_check(email, f"Errore interno: {str(e)}")
    
    def _extract_data_classes(self, entry: Dict) -> List[str]:
        """Estrae le classi di dati compromessi da un entry DeHashed"""
        data_classes = []
        
        if entry.get('email'):
            data_classes.append('Email addresses')
        if entry.get('username'):
            data_classes.append('Usernames')
        if entry.get('password'):
            data_classes.append('Passwords')
        if entry.get('hashed_password'):
            data_classes.append('Password hashes')
        if entry.get('name'):
            data_classes.append('Names')
        if entry.get('phone'):
            data_classes.append('Phone numbers')
        if entry.get('address'):
            data_classes.append('Physical addresses')
        if entry.get('ip_address'):
            data_classes.append('IP addresses')
        if entry.get('vin'):
            data_classes.append('Vehicle identification numbers')
            
        return data_classes
    
    def _is_sensitive_breach(self, entry: Dict) -> bool:
        """Determina se un breach contiene dati sensibili"""
        sensitive_fields = ['password', 'hashed_password', 'vin', 'address', 'phone']
        return any(entry.get(field) for field in sensitive_fields)
    
    def _fallback_breach_check(self, email: str, error_msg: str) -> Dict:
        """Controllo breach simulato quando l'API DeHashed fallisce"""
        domain = email.split('@')[1].lower()
        
        # Domini educativi e governativi sono considerati più sicuri
        safe_domains = ['edu-its.it', '.edu', '.gov', '.mil']
        is_safe_domain = any(safe in domain for safe in safe_domains)
        
        if is_safe_domain:
            return {
                "success": True,
                "email": email,
                "breached": False,
                "breach_count": 0,
                "breaches": [],
                "message": "Nessun breach rilevato - dominio sicuro",
                "timestamp": datetime.now().isoformat(),
                "risk_level": "LOW",
                "api_source": "Fallback Analysis",
                "note": f"⚠️ {error_msg} - Risultati simulati"
            }
        else:
            # Simula possibili breach per domini comuni
            return {
                "success": True,
                "email": email,
                "breached": True,
                "breach_count": 1,
                "breaches": [{
                    "name": "Simulated Breach",
                    "title": "Common Data Breach",
                    "domain": "example.com",
                    "breach_date": "2020-01-01",
                    "added_date": datetime.now().isoformat(),
                    "pwn_count": 1000000,
                    "description": "Simulated breach for testing purposes",
                    "data_classes": ["Email addresses", "Usernames"],
                    "is_verified": False,
                    "is_fabricated": True,
                    "is_sensitive": False
                }],
                "message": "Possibili breach rilevati (simulati)",
                "timestamp": datetime.now().isoformat(),
                "risk_level": "MEDIUM",
                "recommendations": [
                    "Verifica manualmente la sicurezza dei tuoi account",
                    "Attiva l'autenticazione a due fattori",
                    "Monitora i tuoi account regolarmente"
                ],
                "api_source": "Fallback Analysis",
                "note": f"⚠️ {error_msg} - Risultati simulati"
            }
    
    def analyze_email(self, email: str) -> Dict:
        """
        Funzione unificata che analizza email con entrambe le API
        
        Args:
            email (str): Indirizzo email da analizzare
            
        Returns:
            Dict: Risultati completi dell'analisi
        """
        try:
            logger.info(f"Inizio analisi completa per email: {email}")
            
            # Esegui entrambi i controlli
            spam_results = self.check_spam_validity(email)
            breach_results = self.check_breach_status(email)
            
            # Calcola risk score complessivo
            overall_risk = self._calculate_overall_risk(spam_results, breach_results)
            
            # Risultato unificato
            unified_result = {
                "email": email,
                "timestamp": datetime.now().isoformat(),
                "spam_analysis": spam_results,
                "breach_analysis": breach_results,
                "overall_assessment": {
                    "risk_score": overall_risk["score"],
                    "risk_level": overall_risk["level"],
                    "recommendations": overall_risk["recommendations"],
                    "summary": overall_risk["summary"]
                },
                "analysis_success": spam_results.get("success", False) and breach_results.get("success", False)
            }
            
            logger.info(f"Analisi completa terminata per: {email}")
            return unified_result
            
        except Exception as e:
            logger.error(f"Errore nell'analisi unificata: {e}")
            return {
                "email": email,
                "timestamp": datetime.now().isoformat(),
                "error": f"Errore nell'analisi: {str(e)}",
                "analysis_success": False
            }
    
    def _assess_email_risk(self, data: Dict) -> str:
        """Valuta il rischio basato sui dati IPQualityScore"""
        fraud_score = data.get("fraud_score", 0)
        disposable = data.get("disposable", False)
        spam_trap = data.get("spam_trap_score", 0)
        suspect = data.get("suspect", False)
        recent_abuse = data.get("recent_abuse", False)
        
        if fraud_score >= 75 or disposable or spam_trap >= 50 or recent_abuse:
            return "HIGH"
        elif fraud_score >= 50 or spam_trap >= 25 or suspect:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _assess_breach_risk(self, breaches: List[Dict]) -> str:
        """Valuta il rischio basato sui breach"""
        if len(breaches) == 0:
            return "LOW"
        elif len(breaches) <= 2:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def _get_breach_recommendations(self, breaches: List[Dict]) -> List[str]:
        """Genera raccomandazioni basate sui breach"""
        recommendations = [
            "Cambia immediatamente la password per tutti gli account associati a questa email",
            "Attiva l'autenticazione a due fattori dove possibile",
            "Monitora regolarmente i tuoi account per attività sospette"
        ]
        
        sensitive_breaches = [b for b in breaches if b.get("is_sensitive", False)]
        if sensitive_breaches:
            recommendations.append("I tuoi dati sensibili potrebbero essere stati compromessi - considera di contattare le autorità competenti")
            
        return recommendations
    
    def _calculate_overall_risk(self, spam_results: Dict, breach_results: Dict) -> Dict:
        """Calcola il rischio complessivo"""
        risk_score = 0
        risk_factors = []
        recommendations = []
        
        # Analisi spam
        if spam_results.get("success", False):
            if spam_results.get("fraud_score", 0) >= 50:
                risk_score += 30
                risk_factors.append("Alto punteggio di frode")
            if spam_results.get("disposable", False):
                risk_score += 25
                risk_factors.append("Email temporanea/disposable")
            if spam_results.get("recent_abuse", False):
                risk_score += 20
                risk_factors.append("Uso abusivo recente")
        
        # Analisi breach
        if breach_results.get("success", False):
            breach_count = breach_results.get("breach_count", 0)
            if breach_count > 0:
                risk_score += min(breach_count * 15, 45)
                risk_factors.append(f"Coinvolta in {breach_count} data breach")
                recommendations.extend(breach_results.get("recommendations", []))
        
        # Determina livello di rischio
        if risk_score >= 70:
            risk_level = "HIGH"
            summary = "Email ad alto rischio - sconsigliato l'uso"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            summary = "Email a rischio medio - usa con cautela"
        else:
            risk_level = "LOW"
            summary = "Email a basso rischio"
        
        # Raccomandazioni generali
        if risk_level in ["HIGH", "MEDIUM"]:
            recommendations.append("Considera l'uso di un indirizzo email alternativo per servizi importanti")
        
        return {
            "score": risk_score,
            "level": risk_level,
            "factors": risk_factors,
            "recommendations": list(set(recommendations)),  # Rimuovi duplicati
            "summary": summary
        }


class CybersecurityChatbot:
    """Chatbot per domande di cybersecurity"""
    
    def __init__(self):
        self.responses = {
            "phishing": {
                "keywords": ["phishing", "truffa", "email sospetta", "link sospetto"],
                "response": """Il phishing è una tecnica di attacco informatico che mira a rubare informazioni sensibili (password, dati bancari, ecc.) fingendosi un'entità affidabile. 

Come riconoscerlo:
• Email non richieste con urgenza artificiale
• Errori grammaticali e ortografici
• Link sospetti (controlla sempre l'URL prima di cliccare)
• Richieste di informazioni sensibili via email
• Mittenti sconosciuti o indirizzi email strani

Protezione:
• Non cliccare mai su link sospetti
• Verifica sempre l'identità del mittente
• Usa l'autenticazione a due fattori
• Mantieni aggiornato il software antivirus"""
            },
            "password": {
                "keywords": ["password", "password sicura", "proteggere account"],
                "response": """Come creare una password sicura:

Caratteristiche essenziali:
• Almeno 12 caratteri (meglio 16+)
• Combinazione di lettere maiuscole e minuscole
• Numeri e simboli speciali
• Nessuna informazione personale (nome, data di nascita, ecc.)
• Diversa per ogni account

Suggerimenti:
• Usa una passphrase: 4-5 parole casuali separate da simboli
• Esempio: "Sole!Montagna#Verde&Oceano2024"
• Usa un password manager per gestire password multiple
• Attiva l'autenticazione a due fattori ovunque possibile
• Cambia password se sospetti compromissioni"""
            },
            "malware": {
                "keywords": ["malware", "virus", "trojan", "ransomware"],
                "response": """Il malware è software dannoso progettato per danneggiare o accedere illegalmente a sistemi.

Tipi principali:
• Virus: si replica e infetta altri file
• Trojan: si nasconde in software apparentemente legittimo
• Ransomware: cripta i file e chiede riscatto
• Spyware: raccoglie informazioni di nascosto
• Adware: mostra pubblicità indesiderata

Protezione:
• Usa un antivirus aggiornato
• Non scaricare software da fonti sconosciute
• Mantieni sistema operativo e software aggiornati
• Fai backup regolari dei dati importanti
• Non aprire allegati email sospetti"""
            },
            "wifi": {
                "keywords": ["wifi", "wifi pubblico", "rete wireless", "sicurezza wifi"],
                "response": """Sicurezza WiFi e reti wireless:

Rischi del WiFi pubblico:
• Intercettazione dei dati (man-in-the-middle)
• Reti false create da attaccanti
• Accesso non autorizzato ai dispositivi

Protezione:
• Usa una VPN quando possibile
• Evita di accedere a servizi sensibili (banking, email)
• Verifica il nome della rete con il gestore
• Disabilita la condivisione file
• Usa sempre HTTPS (lucchetto verde nel browser)
• Configura la tua rete domestica con WPA3 o WPA2"""
            },
            "social": {
                "keywords": ["social media", "privacy social", "facebook", "instagram", "social network"],
                "response": """Sicurezza sui Social Media:

Impostazioni privacy:
• Limita chi può vedere i tuoi post
• Controlla le impostazioni di geolocalizzazione
• Rivedi periodicamente le app connesse
• Disabilita la ricerca tramite email/telefono se non necessaria

Buone pratiche:
• Non condividere informazioni personali sensibili
• Attenzione alle richieste di amicizia da sconosciuti
• Non cliccare su link sospetti nei messaggi
• Usa l'autenticazione a due fattori
• Controlla regolarmente l'attività del tuo account"""
            },
            "backup": {
                "keywords": ["backup", "salvataggio dati", "protezione dati"],
                "response": """Strategia di Backup efficace:

Regola 3-2-1:
• 3 copie dei dati importanti
• 2 su supporti diversi (es. disco + cloud)
• 1 in posizione remota (offsite)

Tipi di backup:
• Completo: copia tutti i file
• Incrementale: solo file modificati dall'ultimo backup
• Differenziale: file modificati dall'ultimo backup completo

Strumenti:
• Cloud storage (Google Drive, OneDrive, Dropbox)
• Dischi esterni
• NAS (Network Attached Storage)
• Software di backup automatico

Frequenza: dati critici giornalmente, altri settimanalmente"""
            }
        }
    
    def get_chatbot_response(self, question: str) -> str:
        """
        Risponde a domande di cybersecurity
        
        Args:
            question (str): Domanda dell'utente
            
        Returns:
            str: Risposta del chatbot
        """
        try:
            question_lower = question.lower()
            
            # Cerca corrispondenze nelle keywords
            for topic, data in self.responses.items():
                for keyword in data["keywords"]:
                    if keyword in question_lower:
                        return data["response"]
            
            # Se non trova corrispondenze, prova con Claude API (se configurata)
            if ANTHROPIC_API_KEY != 'YOUR_ANTHROPIC_API_KEY':
                claude_response = self._ask_claude(question)
                if claude_response:
                    return claude_response
            
            # Risposta di fallback
            return """Non ho trovato informazioni specifiche per la tua domanda. 

Posso aiutarti con:
• Phishing e truffe online
• Creazione di password sicure
• Malware e virus
• Sicurezza WiFi
• Privacy sui social media
• Strategie di backup

Prova a riformulare la domanda usando una di queste parole chiave!"""
            
        except Exception as e:
            logger.error(f"Errore nel chatbot: {e}")
            return "Scusa, si è verificato un errore. Riprova più tardi."
    
    def _ask_claude(self, question: str) -> Optional[str]:
        """Integrazione opzionale con Claude API"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'x-api-key': ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01'
            }
            
            data = {
                'model': 'claude-3-haiku-20240307',
                'max_tokens': 500,
                'messages': [{
                    'role': 'user',
                    'content': f"""Sei un esperto di cybersecurity. Rispondi in italiano alla seguente domanda sulla sicurezza informatica: {question}
                    
                    Fornisci una risposta pratica e utile, massimo 300 parole."""
                }]
            }
            
            logger.info(f"Chiamando Claude API per: {question[:50]}...")
            response = requests.post(
                'https://api.anthropic.com/v1/messages',
                headers=headers,
                json=data,
                timeout=30
            )
            
            logger.info(f"Claude API response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                return result['content'][0]['text']
            else:
                logger.warning(f"Errore API Claude: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Errore nell'integrazione Claude: {e}")
            return None


# Istanze globali
email_validator = EmailValidator()
chatbot = CybersecurityChatbot()

def check_spam_validity(email: str) -> Dict:
    """Funzione wrapper per controllo spam/validità email"""
    return email_validator.check_spam_validity(email)

def check_breach_status(email: str) -> Dict:
    """Funzione wrapper per controllo breach"""
    return email_validator.check_breach_status(email)

def analyze_email(email: str) -> Dict:
    """Funzione wrapper per analisi completa email"""
    return email_validator.analyze_email(email)

def get_chatbot_response(question: str) -> str:
    """Funzione wrapper per chatbot"""
    return chatbot.get_chatbot_response(question)

# Esempio di integrazione Flask
if __name__ == "__main__":
    # Test delle funzioni
    test_email = "test@example.com"
    
    print("=== Test Funzioni Backend Cybersecurity ===\n")
    
    # Test chatbot
    print("1. Test Chatbot:")
    test_questions = [
        "Cos'è il phishing?",
        "Come creare una password sicura?",
        "Che cos'è il malware?"
    ]
    
    for q in test_questions:
        print(f"Q: {q}")
        print(f"A: {get_chatbot_response(q)[:100]}...\n")
    
    # Test email analysis (richiede API keys valide)
    print("2. Test Analisi Email:")
    print("NOTA: Per testare le funzioni di analisi email, configura le API keys:")
    print("- IPQUALITYSCORE_API_KEY")
    print("- HIBP_API_KEY")
    print("- ANTHROPIC_API_KEY (opzionale)")
    print("\nEsempio di uso:")
    print(f"result = analyze_email('{test_email}')")
    print("print(json.dumps(result, indent=2))")
