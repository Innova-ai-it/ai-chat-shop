import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { scrypt } from "https://esm.sh/@noble/hashes@1.3.0/scrypt"
import { bytesToHex, hexToBytes } from "https://esm.sh/@noble/hashes@1.3.0/utils"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { email, password } = await req.json()

    if (!email || !password) {
      return new Response(
        JSON.stringify({ error: 'Email e password obbligatorie' }),
        { 
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
      {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      }
    )

    // Verifica che l'email esista nella tabella operatori
    const { data: operatoreCheck, error: checkError } = await supabaseAdmin
      .from('operatori')
      .select('id, email, password_hash, user_id, negozio_id')
      .eq('email', email.toLowerCase())
      .single()

    // Se l'email non esiste nella tabella operatori
    if (checkError || !operatoreCheck) {
      return new Response(
        JSON.stringify({ error: 'Email non autorizzata. Contatta l\'amministratore per essere aggiunto al sistema.' }),
        { 
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    // Se l'operatore esiste ma non ha completato la registrazione (password_hash è NULL)
    if (!operatoreCheck.password_hash) {
      return new Response(
        JSON.stringify({ error: 'Registrazione non completata. Vai alla scheda "Registrati" per completare la registrazione.' }),
        { 
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    const operatore = operatoreCheck

    // Verifica la password usando scrypt
    // Il formato salvato è: salt:hash (entrambi in hex)
    const [saltHex, hashHex] = operatore.password_hash.split(':')
    if (!saltHex || !hashHex) {
      return new Response(
        JSON.stringify({ error: 'Formato password_hash non valido' }),
        { 
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }
    
    const salt = hexToBytes(saltHex)
    const storedHash = hexToBytes(hashHex)
    const computedHash = scrypt(password, salt, { N: 16384, r: 8, p: 1, dkLen: 64 })
    
    // Confronta gli hash byte per byte
    const passwordMatch = storedHash.length === computedHash.length &&
      storedHash.every((byte, i) => byte === computedHash[i])
    
    if (!passwordMatch) {
      return new Response(
        JSON.stringify({ error: 'Password non corretta' }),
        { 
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    // Se non ha user_id, crealo o recuperalo (per retrocompatibilità)
    let userId = operatore.user_id
    if (!userId) {
      // Prova prima a recuperare l'utente esistente in Auth
      const { data: usersList } = await supabaseAdmin.auth.admin.listUsers()
      const existingUser = usersList?.users?.find(u => u.email?.toLowerCase() === email.toLowerCase())
      
      if (existingUser) {
        userId = existingUser.id
      } else {
        // Crea nuovo utente in Auth
        const { data: authUser, error: authError } = await supabaseAdmin.auth.admin.createUser({
          email: email.toLowerCase(),
          email_confirm: true,
          password: password
        })

        if (authError || !authUser.user) {
          return new Response(
            JSON.stringify({ error: 'Errore nella creazione sessione: ' + (authError?.message || 'Sconosciuto') }),
            { 
              status: 500,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            }
          )
        }

        userId = authUser.user.id
      }
      
      // Aggiorna operatori con user_id
      await supabaseAdmin
        .from('operatori')
        .update({ user_id: userId })
        .eq('id', operatore.id)
    }

    // Genera sessione
    const { data: { session }, error: sessionError } = await supabaseAdmin.auth.signInWithPassword({
      email: email.toLowerCase(),
      password: password
    })

    if (sessionError || !session) {
      return new Response(
        JSON.stringify({ error: 'Errore nella creazione sessione' }),
        { 
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    return new Response(
      JSON.stringify({ 
        success: true,
        session: {
          access_token: session.access_token,
          refresh_token: session.refresh_token,
          expires_in: session.expires_in,
          token_type: session.token_type,
          user: session.user
        }
      }),
      { 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    )

  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { 
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    )
  }
})

