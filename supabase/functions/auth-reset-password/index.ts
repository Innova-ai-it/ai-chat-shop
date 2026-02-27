import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { hash } from "https://deno.land/x/bcrypt@v0.4.1/mod.ts"
import { crypto } from "https://deno.land/std@0.168.0/crypto/mod.ts"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { email, token, newPassword } = await req.json()

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

    // FASE 1: Richiesta reset (solo email)
    if (!token && !newPassword) {
      if (!email) {
        return new Response(
          JSON.stringify({ error: 'Email obbligatoria' }),
          { 
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          }
        )
      }

      // Verifica che email esista e sia registrata
      const { data: operatore, error: operatoreError } = await supabaseAdmin
        .from('operatori')
        .select('id, email, user_id')
        .eq('email', email.toLowerCase())
        .not('password_hash', 'is', null)
        .single()

      if (operatoreError || !operatore) {
        // Per sicurezza, non rivelare se l'email esiste o meno
        return new Response(
          JSON.stringify({ 
            success: true,
            message: 'Se l\'email è registrata, riceverai un link per reimpostare la password.'
          }),
          { 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          }
        )
      }

      // Genera token sicuro
      const resetToken = crypto.randomUUID()
      const expiresAt = new Date()
      expiresAt.setHours(expiresAt.getHours() + 1) // Token valido 1 ora

      // Salva token nel database
      await supabaseAdmin
        .from('operatori')
        .update({ 
          reset_token: resetToken,
          reset_token_expires: expiresAt.toISOString()
        })
        .eq('id', operatore.id)

      // Invia email (qui dovresti integrare un servizio email)
      // Per ora restituiamo il token (in produzione usa email)
      const dashboardUrl = Deno.env.get('DASHBOARD_URL') || 'https://dashboard.example.com'
      const resetLink = `${dashboardUrl}/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`

      // TODO: Invia email con resetLink
      // Per ora logghiamo (in produzione rimuovi)
      console.log('Reset link:', resetLink)

      return new Response(
        JSON.stringify({ 
          success: true,
          message: 'Link di reset inviato via email.',
          // RIMUOVI IN PRODUZIONE - solo per test
          resetLink: resetLink
        }),
        { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    // FASE 2: Reset password con token
    if (token && newPassword) {
      if (!email || !newPassword || newPassword.length < 6) {
        return new Response(
          JSON.stringify({ error: 'Email, token e nuova password obbligatori. Password minimo 6 caratteri.' }),
          { 
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          }
        )
      }

      // Verifica token
      const { data: operatore, error: operatoreError } = await supabaseAdmin
        .from('operatori')
        .select('id, email, user_id, reset_token, reset_token_expires')
        .eq('email', email.toLowerCase())
        .eq('reset_token', token)
        .single()

      if (operatoreError || !operatore) {
        return new Response(
          JSON.stringify({ error: 'Token non valido o scaduto' }),
          { 
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          }
        )
      }

      // Verifica scadenza
      if (new Date(operatore.reset_token_expires) < new Date()) {
        return new Response(
          JSON.stringify({ error: 'Token scaduto. Richiedi un nuovo reset.' }),
          { 
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          }
        )
      }

      // Hash nuova password
      const passwordHash = await hash(newPassword)

      // Aggiorna password
      const { error: updateError } = await supabaseAdmin
        .from('operatori')
        .update({ 
          password_hash: passwordHash,
          reset_token: null,
          reset_token_expires: null
        })
        .eq('id', operatore.id)

      if (updateError) {
        return new Response(
          JSON.stringify({ error: 'Errore nell\'aggiornamento password' }),
          { 
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          }
        )
      }

      // Aggiorna password anche in Supabase Auth
      if (operatore.user_id) {
        await supabaseAdmin.auth.admin.updateUserById(
          operatore.user_id,
          { password: newPassword }
        )
      }

      return new Response(
        JSON.stringify({ 
          success: true,
          message: 'Password reimpostata con successo!'
        }),
        { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      )
    }

    return new Response(
      JSON.stringify({ error: 'Parametri non validi' }),
      { 
        status: 400,
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

