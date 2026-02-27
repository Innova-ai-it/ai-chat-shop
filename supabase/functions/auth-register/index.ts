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

    if (!email || !password || password.length < 6) {
      return new Response(
        JSON.stringify({ error: 'Email e password obbligatorie. Password minimo 6 caratteri.' }),
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

    // Verifica che l'email esista nella tabella operatori E che password_hash sia NULL
    const { data: operatore, error: operatoreError } = await supabaseAdmin
      .from('operatori')
      .select('id, email, password_hash, user_id, negozio_id')
      .eq('email', email.toLowerCase())
      .is('password_hash', null)
      .single()

    if (operatoreError || !operatore) {
      return new Response(
        JSON.stringify({ error: 'Email non autorizzata o già registrata. Se hai già un account, usa il login.' }),
        { 
          status: 403,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    // Hash della password usando scrypt
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const passwordHashBytes = scrypt(password, salt, { N: 16384, r: 8, p: 1, dkLen: 64 })
    const passwordHash = bytesToHex(salt) + ':' + bytesToHex(passwordHashBytes)

    // Gestione utente Auth
    let userId
    
    // CASO 1: L'operatore ha già un user_id (utente esiste in Auth ma registrazione incompleta)
    if (operatore.user_id) {
      userId = operatore.user_id
      
      // Verifica che l'utente esista ancora in Auth
      const { data: existingAuthUser, error: getUserError } = await supabaseAdmin.auth.admin.getUserById(userId)
      
      if (getUserError || !existingAuthUser.user) {
        // Se l'utente non esiste più in Auth, crealo
        const { data: newAuthUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
          email: email.toLowerCase(),
          email_confirm: true,
          password: password
        })
        
        if (createError || !newAuthUser.user) {
          return new Response(
            JSON.stringify({ error: 'Errore nella creazione account: ' + (createError?.message || 'Sconosciuto') }),
            { 
              status: 500,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            }
          )
        }
        
        userId = newAuthUser.user.id
      } else {
        // Utente esiste, aggiorna solo la password
        const { data: updatedUser, error: updateError } = await supabaseAdmin.auth.admin.updateUserById(
          userId,
          { password: password }
        )
        
        if (updateError || !updatedUser.user) {
          return new Response(
            JSON.stringify({ error: 'Errore nell\'aggiornamento password: ' + (updateError?.message || 'Sconosciuto') }),
            { 
              status: 500,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            }
          )
        }
      }
    } 
    // CASO 2: L'operatore NON ha user_id (prima registrazione)
    else {
      // Prova a creare l'utente in Auth
      const { data: newAuthUser, error: authError } = await supabaseAdmin.auth.admin.createUser({
        email: email.toLowerCase(),
        email_confirm: true,
        password: password
      })

      if (authError) {
        // Se l'errore indica che l'utente esiste già, recuperalo
        const errorMsg = authError.message?.toLowerCase() || ''
        if (errorMsg.includes('already') || errorMsg.includes('exists') || errorMsg.includes('registered')) {
          // Cerca l'utente per email
          const { data: usersList, error: listError } = await supabaseAdmin.auth.admin.listUsers()
          
          if (listError) {
            return new Response(
              JSON.stringify({ error: 'Errore nel recupero utente esistente: ' + listError.message }),
              { 
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
              }
            )
          }
          
          const existingUser = usersList?.users?.find(u => u.email?.toLowerCase() === email.toLowerCase())
          
          if (existingUser) {
            userId = existingUser.id
            // Aggiorna la password
            const { data: updatedUser, error: updateError } = await supabaseAdmin.auth.admin.updateUserById(
              userId,
              { password: password }
            )
            
            if (updateError || !updatedUser.user) {
              return new Response(
                JSON.stringify({ error: 'Errore nell\'aggiornamento password: ' + (updateError?.message || 'Sconosciuto') }),
                { 
                  status: 500,
                  headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                }
              )
            }
          } else {
            return new Response(
              JSON.stringify({ error: 'Errore: utente già registrato ma non trovato. Contatta l\'amministratore.' }),
              { 
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
              }
            )
          }
        } else {
          // Altro tipo di errore
          return new Response(
            JSON.stringify({ error: 'Errore nella creazione account: ' + authError.message }),
            { 
              status: 500,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            }
          )
        }
      } else if (!newAuthUser.user) {
        return new Response(
          JSON.stringify({ error: 'Errore nella creazione account: utente non creato' }),
          { 
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          }
        )
      } else {
        // Utente creato con successo
        userId = newAuthUser.user.id
      }
    }

    // Aggiorna operatori con password_hash e user_id (se non era già presente)
    const updateData: any = { password_hash: passwordHash }
    if (!operatore.user_id) {
      updateData.user_id = userId
    }
    
    const { error: updateError } = await supabaseAdmin
      .from('operatori')
      .update(updateData)
      .eq('id', operatore.id)

    if (updateError) {
      return new Response(
        JSON.stringify({ error: 'Errore nel salvataggio: ' + updateError.message }),
        { 
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    // Genera sessione per login automatico
    const { data: { session }, error: sessionError } = await supabaseAdmin.auth.signInWithPassword({
      email: email.toLowerCase(),
      password: password
    })

    if (sessionError || !session) {
      return new Response(
        JSON.stringify({ error: 'Registrazione completata ma errore nel login automatico. Prova ad accedere manualmente.' }),
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