// Luminexus — robô do WhatsApp (migração 0074). Roda no GitHub Actions só quando há trabalho (o Worker do site dispara
// o workflow) e termina sozinho: não precisa de servidor ligado.
//   1. Pergunta ao banco o que fazer (whatsapp_robo_trabalho): PAREAR (gera o código para digitar no celular) ou ENVIAR.
//   2. Abre a sessão do número da igreja (chaves do Baileys guardadas no banco, criptografadas com CHAVE_SESSAO).
//   3. ENVIAR: pega uma mensagem por vez (whatsapp_proximo — o banco aplica horário, limites e aquecimento), confere se o
//      número tem WhatsApp, mostra "digitando…", envia (com imagem, quando a fila traz uma: 0205), marca o resultado e
//      espera um intervalo aleatório. Para no fim
//      do lote; o próximo lote só começa depois da pausa (o Worker cuida disso). Recibos (entregue/lida) que chegarem
//      enquanto estiver conectado, inclusive atrasados de rodadas anteriores, vão para whatsapp_recibo.
// Nada pessoal no log (público: o repositório do robô é aberto de propósito): só ids e contagens.
// Variáveis: SUPABASE_URL, SUPABASE_ANON_KEY, SEGREDO_WHATSAPP, CHAVE_SESSAO (64 hex), TEMPO_MAX_MIN (padrão 15).
import { createCipheriv, createDecipheriv, randomBytes, randomInt } from 'node:crypto'
import makeWASocket, { BufferJSON, DisconnectReason, initAuthCreds, proto, Browsers } from 'baileys'
import pino from 'pino'

const { SUPABASE_URL, SUPABASE_ANON_KEY, SEGREDO_WHATSAPP, CHAVE_SESSAO } = process.env
const TEMPO_MAX = Number(process.env.TEMPO_MAX_MIN || 15) * 60_000
const inicio = Date.now()
const restante = () => TEMPO_MAX - (Date.now() - inicio)
const dormir = (ms) => new Promise((r) => setTimeout(r, ms))
// o log é público (repositório luminexus-robo): além de só registrar ids e contagens, a saída apaga qualquer sequência de
// 8+ dígitos (telefone) e jid (@s.whatsapp.net) que apareça numa mensagem de erro de biblioteca
const limpar = (t) => t.replace(/\d{8,}(@[\w.]+)?/g, '***').replace(/\S+@(s\.whatsapp\.net|lid|g\.us)/g, '***')
const log = (...a) => process.stdout.write(`${new Date().toISOString().slice(11, 19)} ${limpar(a.join(' '))}\n`)
// a criptografia do WhatsApp (libsignal) imprime sessões e chaves no console: o log do Actions fica guardado, então cala
for (const k of ['log', 'info', 'warn', 'debug', 'error', 'trace']) console[k] = () => {}
if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SEGREDO_WHATSAPP || !/^[0-9a-f]{64}$/i.test(CHAVE_SESSAO || '')) {
  log('Faltam variáveis: SUPABASE_URL, SUPABASE_ANON_KEY, SEGREDO_WHATSAPP, CHAVE_SESSAO (64 hex)'); process.exit(1)
}

async function rpc(fn, args) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fn}`, {
    method: 'POST',
    headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SUPABASE_ANON_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ p_segredo: SEGREDO_WHATSAPP, ...args }),
  })
  // o log do Actions é público: do erro do banco vai só a mensagem curta (nunca "details"/"hint", que podem trazer dados)
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(`${fn}: ${r.status} ${String(j?.message ?? '').slice(0, 160)}`) }
  const t = await r.text()
  return t ? JSON.parse(t) : null
}
const estado = (igreja, p) => rpc('whatsapp_robo_estado', { p_igreja: igreja, p }).catch((e) => log('estado:', e.message))

// imagem da mensagem (0205): link assinado do Storage gerado pela tela. Só imagem de verdade (pelos primeiros bytes),
// até 5 MB; WebP/GIF/HEIC viram JPEG (o WhatsApp mostra WebP como figurinha). Falhou ou venceu: null = vai só o texto.
const IMAGEM_SITE = new URL(SUPABASE_URL).host
async function baixarImagem(url) {
  try {
    if (new URL(url).host !== IMAGEM_SITE) return null
    const r = await fetch(url, { signal: AbortSignal.timeout(30_000) })
    if (!r.ok) return null
    let b = Buffer.from(await r.arrayBuffer())
    if (b.length > 5 * 1024 * 1024) return null
    if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return { imagem: b, tipo: 'image/jpeg' }
    if (b[0] === 0x89 && b.toString('latin1', 1, 4) === 'PNG') return { imagem: b, tipo: 'image/png' }
    const { default: sharp } = await import('sharp')
    b = await sharp(b).rotate().jpeg({ quality: 85 }).toBuffer()
    return { imagem: b, tipo: 'image/jpeg' }
  } catch { return null }
}
const LEGENDA_MAX = 1000   // texto maior vai numa mensagem logo depois da imagem

// ------------------------------------------------------------------ sessão criptografada no banco
const CHAVE = Buffer.from(CHAVE_SESSAO, 'hex')
function cifrar(obj) {
  const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', CHAVE, iv)
  const dados = Buffer.concat([c.update(JSON.stringify(obj, BufferJSON.replacer), 'utf8'), c.final()])
  return Buffer.concat([iv, c.getAuthTag(), dados]).toString('base64')
}
function decifrar(txt) {
  const b = Buffer.from(txt, 'base64'), d = createDecipheriv('aes-256-gcm', CHAVE, b.subarray(0, 12))
  d.setAuthTag(b.subarray(12, 28))
  return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'), BufferJSON.reviver)
}

/** estado de autenticação do Baileys em memória, carregado do banco e gravado aos poucos (só o que mudou) */
async function sessaoDoBanco(igreja) {
  // {chave: valor cifrado} num JSON só (0076): a sessão passa de 1.000 chaves (mapa de contatos)
  const salvas = (await rpc('whatsapp_sessao_ler', { p_igreja: igreja })) ?? {}
  const mem = new Map()
  for (const [chave, valor] of Object.entries(salvas)) { try { mem.set(chave, decifrar(valor)) } catch { log('sessão: chave ilegível descartada') } }
  log(`igreja ${igreja}: sessão com ${mem.size} chave(s)`)
  const creds = mem.get('creds') ?? initAuthCreds()
  const sujas = new Map()   // chave -> valor cifrado | null (apagar)
  let gravando = Promise.resolve(), timer = null
  const marcar = (k, v) => { sujas.set(k, v == null ? null : cifrar(v)); if (!timer) timer = setTimeout(gravar, 1500) }
  function gravar() {
    timer = null
    if (!sujas.size) return gravando
    const itens = Object.fromEntries(sujas); sujas.clear()
    gravando = gravando.then(() => rpc('whatsapp_sessao_gravar', { p_igreja: igreja, p_itens: itens })).catch((e) => {
      log('sessão: falha ao gravar, tenta de novo', e.message)
      for (const [k, v] of Object.entries(itens)) if (!sujas.has(k)) sujas.set(k, v)
    })
    return gravando
  }
  return {
    novo: !mem.has('creds'),
    state: {
      creds,
      keys: {
        get: async (tipo, ids) => {
          const r = {}
          for (const id of ids) {
            let v = mem.get(`${tipo}-${id}`)
            if (tipo === 'app-state-sync-key' && v) v = proto.Message.AppStateSyncKeyData.fromObject(v)
            r[id] = v
          }
          return r
        },
        set: async (dados) => {
          for (const tipo in dados) for (const id in dados[tipo]) {
            const v = dados[tipo][id], k = `${tipo}-${id}`
            if (v) mem.set(k, v); else mem.delete(k)
            marcar(k, v)
          }
        },
      },
    },
    salvarCreds: () => marcar('creds', creds),
    descarregar: async () => { if (timer) clearTimeout(timer); await gravar(); await gravando; if (sujas.size) await gravar() },
  }
}

// ------------------------------------------------------------------ conexão
const STATUS = { 3: 'ENTREGUE', 4: 'LIDO', 5: 'LIDO' }   // proto.WebMessageInfo.Status: DELIVERY_ACK, READ, PLAYED

/** conecta e devolve o socket aberto; refaz a conexão quando o WhatsApp pede (515 depois de parear) */
function conectar(igreja, sessao, { parear, numero, aoCodigo }) {
  const enviadas = new Map()   // id -> mensagem (o celular pode pedir reenvio para decifrar)
  return new Promise((resolve, reject) => {
    let codigoPedido = false, encerrado = false
    const abrir = () => {
      const sock = makeWASocket({
        auth: sessao.state,
        logger: pino({ level: 'silent' }),
        browser: Browsers.ubuntu('Chrome'),
        markOnlineOnConnect: false,
        syncFullHistory: false,
        shouldSyncHistoryMessage: () => false,
        fireInitQueries: false,
        generateHighQualityLinkPreview: false,
        getMessage: async (key) => enviadas.get(key.id),
      })
      sock.enviadas = enviadas
      sock.ev.on('creds.update', sessao.salvarCreds)
      sock.ev.on('messages.update', (lista) => {
        for (const { key, update } of lista) {
          const st = STATUS[update?.status]
          if (key?.fromMe && st) rpc('whatsapp_recibo', { p_igreja: igreja, p_mensagem_id: key.id, p_status: st }).catch(() => {})
        }
      })
      sock.ev.on('connection.update', async (u) => {
        if (u.qr && parear && !codigoPedido && !sessao.state.creds.registered) {
          codigoPedido = true
          try { aoCodigo(await sock.requestPairingCode(numero)) } catch (e) { reject(e) }
        }
        if (u.connection === 'open') { encerrado = true; resolve(sock) }
        if (u.connection === 'close') {
          const cod = u.lastDisconnect?.error?.output?.statusCode
          if (cod === DisconnectReason.restartRequired) { log('reconectando (pedido do WhatsApp)'); abrir(); return }
          if (!encerrado) reject(Object.assign(new Error(`conexão fechada (${cod ?? '?'})`), { codigo: cod }))
          else sock.caiu = cod ?? true
        }
      })
    }
    abrir()
  })
}

// ------------------------------------------------------------------ tarefas
async function parearIgreja(t) {
  const sessao = await sessaoDoBanco(t.igreja_id)
  await estado(t.igreja_id, { rodando_seg: 300 })
  log(`igreja ${t.igreja_id}: pareando`)
  try {
    const sock = await Promise.race([
      conectar(t.igreja_id, sessao, {
        parear: true, numero: t.numero,
        aoCodigo: (codigo) => { log(`igreja ${t.igreja_id}: código gerado`); estado(t.igreja_id, { codigo, rodando_seg: 300 }) },
      }),
      dormir(Math.min(4 * 60_000, restante())).then(() => { throw new Error('o código não foi digitado a tempo') }),
    ])
    await dormir(8000)   // deixa o WhatsApp terminar de mandar as chaves iniciais
    await sessao.descarregar()
    const numero = (sock.user?.id ?? '').split(/[:@]/)[0] || t.numero
    await estado(t.igreja_id, { situacao: 'CONECTADO', numero, aviso: null, rodando_seg: 0 })
    log(`igreja ${t.igreja_id}: conectado`)
    sock.end(undefined)
  } catch (e) {
    await sessao.descarregar().catch(() => {})
    await estado(t.igreja_id, { situacao: 'DESCONECTADO', aviso: `Pareamento não concluído: ${e.message}. Peça um código novo.`, rodando_seg: 0 })
    log(`igreja ${t.igreja_id}: pareamento falhou: ${e.message}`)
  }
}

async function enviarIgreja(t) {
  const sessao = await sessaoDoBanco(t.igreja_id)
  if (sessao.novo) { await estado(t.igreja_id, { situacao: 'DESCONECTADO', aviso: 'Sessão não encontrada: conecte o número de novo.', rodando_seg: 0 }); return }
  await estado(t.igreja_id, { rodando_seg: 120 })
  let sock
  try {
    sock = await Promise.race([conectar(t.igreja_id, sessao, {}), dormir(90_000).then(() => { throw new Error('tempo esgotado ao conectar') })])
  } catch (e) {
    await sessao.descarregar().catch(() => {})
    if (e.codigo === DisconnectReason.loggedOut) {
      await estado(t.igreja_id, { situacao: 'DESCONECTADO', aviso: 'O celular desconectou este aparelho (WhatsApp › Dispositivos conectados). Conecte de novo.', rodando_seg: 0 })
    } else {
      await estado(t.igreja_id, { aviso: `Não conectou: ${e.message}`, rodando_seg: 0 })
    }
    log(`igreja ${t.igreja_id}: não conectou: ${e.message}`)
    return
  }
  log(`igreja ${t.igreja_id}: conectado, lote de até ${t.lote}`)
  await dormir(5000)   // recibos atrasados e notificações chegam logo ao conectar
  let n = 0
  while (n < t.lote && restante() > 3 * 60_000 && !sock.caiu) {
    await estado(t.igreja_id, { rodando_seg: 180 })
    const [m] = (await rpc('whatsapp_proximo', { p_igreja: t.igreja_id })) ?? []
    if (!m) break
    try {
      const [conta] = (await sock.onWhatsApp(m.telefone)) ?? []
      if (!conta?.exists) { await rpc('whatsapp_marcar', { p_id: m.id, p_resultado: 'SEM_WHATSAPP' }); log(`#${m.id} sem WhatsApp`); continue }
      // "digitando…" por alguns segundos, como uma pessoa
      await sock.presenceSubscribe(conta.jid).catch(() => {})
      await sock.sendPresenceUpdate('composing', conta.jid).catch(() => {})
      await dormir(randomInt(2500, 6000))
      await sock.sendPresenceUpdate('paused', conta.jid).catch(() => {})
      const img = m.imagem_url ? await baixarImagem(m.imagem_url) : null
      if (m.imagem_url && !img) log(`#${m.id} imagem não baixou: vai só o texto`)
      let r
      if (img && m.texto.length <= LEGENDA_MAX) {
        r = await sock.sendMessage(conta.jid, { image: img.imagem, mimetype: img.tipo, caption: m.texto })
      } else {
        if (img) {
          const ri = await sock.sendMessage(conta.jid, { image: img.imagem, mimetype: img.tipo })
          if (ri?.key?.id) sock.enviadas.set(ri.key.id, ri.message)
          await dormir(randomInt(1500, 3500))
        }
        r = await sock.sendMessage(conta.jid, { text: m.texto })
      }
      if (r?.key?.id) sock.enviadas.set(r.key.id, r.message)
      await rpc('whatsapp_marcar', { p_id: m.id, p_resultado: 'OK', p_mensagem_id: r?.key?.id ?? null })
      n++
      log(`#${m.id} enviada (${n})`)
    } catch (e) {
      await rpc('whatsapp_marcar', { p_id: m.id, p_resultado: 'FALHA', p_erro: String(e?.message ?? e).slice(0, 300) }).catch(() => {})
      log(`#${m.id} falhou: ${e?.message ?? e}`)
      if (sock.caiu) break
    }
    if (n < t.lote) await dormir(randomInt(t.intervalo_min * 1000, t.intervalo_max * 1000 + 1))
  }
  await dormir(15_000)   // tempo para as confirmações de entrega das últimas
  await sessao.descarregar()
  await estado(t.igreja_id, { rodando_seg: 0, ...(sock.caiu === DisconnectReason.loggedOut ? { situacao: 'DESCONECTADO', aviso: 'O celular desconectou este aparelho. Conecte de novo.' } : {}) })
  log(`igreja ${t.igreja_id}: ${n} enviada(s) neste lote`)
  try { sock.end(undefined) } catch { /* já fechado */ }
}

// ------------------------------------------------------------------ principal
try {
  const tarefas = (await rpc('whatsapp_robo_trabalho', {})) ?? []
  log(`${tarefas.length} igreja(s) com trabalho`)
  // igrejas em paralelo: cada uma com seu número, sua conexão e seus limites (uma não espera a outra)
  await Promise.all(tarefas.map(async (t) => {
    try { await (t.modo === 'PAREAR' ? parearIgreja(t) : enviarIgreja(t)) }
    catch (e) { log(`igreja ${t.igreja_id}: erro: ${e.message}`); await estado(t.igreja_id, { rodando_seg: 0 }) }
  }))
} catch (e) {
  log('erro:', e.message); process.exitCode = 1
}
setTimeout(() => process.exit(), 2000)   // o socket do Baileys deixa temporizadores vivos
