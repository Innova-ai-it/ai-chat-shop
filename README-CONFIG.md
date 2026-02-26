# ⚙️ Configurazione Dashboard

## 📋 Setup Iniziale

1. **Copia il file di esempio**:
   ```bash
   cp config.example.js config.js
   ```

2. **Modifica `config.js`** con i tuoi valori:
   - `SUPABASE_URL`: URL del tuo progetto Supabase
   - `SUPABASE_ANON_KEY`: Chiave anonima di Supabase
   - `N8N_WEBHOOK_URL`: URL del tuo webhook n8n
   - `ADMIN_EMAIL`: La tua email admin

## 🔒 Sicurezza

- ✅ `config.js` è in `.gitignore` e **NON verrà committato** su GitHub
- ✅ `config.example.js` è committato come template (senza dati sensibili)
- ✅ I dati sensibili rimangono locali sul tuo computer

## 📝 Per Nuovi Collaboratori

Quando qualcuno clona il repository:

1. Copia `config.example.js` come `config.js`
2. Modifica i valori in `config.js` con le proprie credenziali
3. Il file `config.js` non verrà mai committato accidentalmente

## ⚠️ Importante

**NON committare mai `config.js` su GitHub!** Contiene dati sensibili.

