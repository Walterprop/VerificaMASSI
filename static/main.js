let mode = "general"; // modalità predefinita

function chooseMode(selected) {
  mode = selected;
  const title = document.getElementById("chat-title");
  if (mode === "spam") {
    title.innerText = "🔴 Analisi SPAM (email singola)";
  } else if (mode === "breach") {
    title.innerText = "🔵 Verifica Email Compromessa";
  } else if (mode === "check") {
    title.innerText = "🧪 Analisi Completa (Spam + Breach)";
  } else {
    title.innerText = "🤖 CyberMatrix Chatbot";
  }
}

function submit() {
  const input = document.getElementById("inputField").value.trim();
  const output = document.getElementById("output");
  output.innerText = "⏳ Elaborazione in corso...";

  if (!input) {
    output.innerText = "⚠️ Inserisci un testo valido.";
    return;
  }

  if (mode === "spam") {
    fetch("/check_spam", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: input })
    })
      .then(res => res.json())
      .then(data => {
        output.innerHTML = `
          📧 Email: ${input}<br>
          ✉️ Valida: ${data.valid ? "✅ Sì" : "❌ No"}<br>
          🚫 Spam: ${data.spam ? "❗ Sospetta" : "✔️ Sicura"}
        `;
      })
      .catch(() => {
        output.innerText = "❌ Errore durante il controllo spam.";
      });

  } else if (mode === "breach") {
    fetch("/check_breach", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: input })
    })
      .then(res => res.json())
      .then(data => {
        if (data.found === false) {
          output.innerText = `🛡️ Nessuna violazione rilevata per ${input}`;
        } else {
          output.innerHTML = `
            🛑 Email compromessa!<br>
            🔍 Servizi violati:<br>
            <ul>${data.breaches.map(b => `<li>${b}</li>`).join("")}</ul>
          `;
        }
      })
      .catch(() => {
        output.innerText = "❌ Errore durante il controllo breach.";
      });

  } else if (mode === "check") {
    fetch("/check_email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: input })
    })
      .then(res => res.json())
      .then(data => {
        output.innerHTML = `
          📧 Email: ${input}<br>
          ✉️ Valida: ${data.spam_check?.valid ? "✅ Sì" : "❌ No"}<br>
          🚫 Spam: ${data.spam_check?.spam ? "❗ Sospetta" : "✔️ Sicura"}<br>
          🛡️ Breach: ${
            data.breach_check?.found
              ? `<ul>${data.breach_check.breaches.map(b => `<li>${b}</li>`).join("")}</ul>`
              : "✅ Nessuna violazione rilevata"
          }
        `;
      })
      .catch(() => {
        output.innerText = "❌ Errore durante l'analisi completa.";
      });

  } else {
    // chatbot
    fetch("/ask_chatbot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: input })
    })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          output.innerText = "🤖 " + data.response;
        } else {
          output.innerText = "❌ Errore nella risposta: " + (data.error || "ignoto");
        }
      })
      .catch(() => {
        output.innerText = "❌ Errore nella richiesta al chatbot.";
      });
  }
}
