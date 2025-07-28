// Corrigido: normalização de acentos, arrays para user_data, validação robusta FBP/FBC

import type { NextApiRequest, NextApiResponse } from "next";
import crypto from "crypto";
import zlib from "zlib";

const PIXEL_ID = "765087775987515";
const ACCESS_TOKEN = "EAAQfmxkTTZCcBPHGbA2ojC29bVbNPa6GM3nxMxsZC29ijBmuyexVifaGnrjFZBZBS6LEkaR29X3tc5TWn4SHHffeXiPvexZAYKP5mTMoYGx5AoVYaluaqBTtiKIjWALxuMZAPVcBk1PuYCb0nJfhpzAezh018LU3cT45vuEflMicoQEHHk3H5YKNVAPaUZC6yzhcQZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

// ✅ CORREÇÃO CRÍTICA: Removido .toLowerCase() para preservar fbclid
function hashSHA256(value: string) {
  if (!value || typeof value !== 'string') {
    console.warn('⚠️ hashSHA256: Valor inválido:', value);
    return null;
  }
  return crypto.createHash("sha256")
    .update(
      value
        .trim()
        // ❌ REMOVIDO: .toLowerCase() - Esta linha modificava o fbclid!
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "") // Remove acentos
    )
    .digest("hex");
}

// ✅ NOVA FUNÇÃO: Processamento robusto do FBC
function processFbc(fbc: string): string | null {
  if (!fbc || typeof fbc !== 'string') {
    console.warn('⚠️ FBC inválido:', fbc);
    return null;
  }

  const trimmedFbc = fbc.trim();
  
  // Formato padrão: fb.1.timestamp.fbclid
  const fbcPattern = /^fb\.1\.[0-9]+\.[A-Za-z0-9_-]+$/;
  if (fbcPattern.test(trimmedFbc)) {
    console.log('✅ FBC válido (formato padrão):', trimmedFbc);
    return trimmedFbc;
  }
  
  // Formato fbclid puro (sem prefixo)
  const fbclidPattern = /^[A-Za-z0-9_-]+$/;
  if (fbclidPattern.test(trimmedFbc)) {
    const timestamp = Math.floor(Date.now() / 1000);
    const formattedFbc = `fb.1.${timestamp}.${trimmedFbc}`;
    console.log('✅ FBC formatado de fbclid puro:', formattedFbc);
    return formattedFbc;
  }
  
  // Formato com prefixo fbclid=
  if (trimmedFbc.startsWith('fbclid=')) {
    const fbclid = trimmedFbc.substring(7);
    if (fbclidPattern.test(fbclid)) {
      const timestamp = Math.floor(Date.now() / 1000);
      const formattedFbc = `fb.1.${timestamp}.${fbclid}`;
      console.log('✅ FBC formatado de fbclid com prefixo:', formattedFbc);
      return formattedFbc;
    }
  }
  
  console.warn('⚠️ FBC formato inválido:', trimmedFbc);
  return null;
}

const RATE_LIMIT = 30;
const rateLimitMap = new Map();

function rateLimit(ip: string): boolean {
  const now = Date.now();
  const windowMs = 60000;
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const timestamps = rateLimitMap.get(ip)!.filter((t: number) => now - t < windowMs);
  if (timestamps.length >= RATE_LIMIT) return false;
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  if (rateLimitMap.size > 1000) {
    const oldestKey = rateLimitMap.keys().next().value;
    rateLimitMap.delete(oldestKey);
  }
  return true;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const startTime = Date.now();
  const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
  const userAgent = req.headers["user-agent"] || "";
  const origin = req.headers.origin;

  const ALLOWED_ORIGINS = [
    "https://www.digitalpaisagismo.com",
    "https://digitalpaisagismo.com", // <-- Adicionado domínio sem www
    "https://cap.digitalpaisagismo.com",
    "https://atendimento.digitalpaisagismo.com",
    "https://projeto.digitalpaisagismo.com",
    "https://www.projeto.digitalpaisagismo.com",
    "http://localhost:3000",
  ];

  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGINS.includes(origin!) ? origin! : "https://www.digitalpaisagismo.com");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });
  if (!rateLimit(ip)) return res.status(429).json({ error: "Limite de requisições excedido", retry_after: 60 });

  try {
    if (!req.body?.data || !Array.isArray(req.body.data)) {
      return res.status(400).json({ error: "Payload inválido - campo 'data' obrigatório" });
    }

    const enrichedData = req.body.data.map((event: any) => {
      // Garantir session_id único se não vier do frontend
      let sessionId = event.session_id;
      if (!sessionId) {
        if (req.cookies && req.cookies.session_id) {
          sessionId = req.cookies.session_id;
        } else {
          sessionId = `sess_${Date.now()}_${Math.random().toString(36).substr(2, 10)}`;
        }
      }
      // ✅ SEM PII: Usar apenas session_id para external_id
      const externalId = sessionId ? hashSHA256(sessionId) : null;
      
      const eventId = event.event_id || `evt_${Date.now()}_${Math.random().toString(36).substr(2, 10)}`;
      const eventName = event.event_name || "Lead";
      const eventSourceUrl = event.event_source_url || origin || req.headers.referer || "https://www.digitalpaisagismo.com";
      const eventTime = event.event_time ? Math.floor(Number(event.event_time)) : Math.floor(Date.now() / 1000);
      const actionSource = event.action_source || "website";

      // Padronizar custom_data
      const customData = { ...event.custom_data };
      if (["PageView", "ViewContent", "VideoProgress"].includes(eventName)) {
        delete customData.value;
        delete customData.currency;
      }
      // Para VideoProgress, garantir progress, duration, current_time
      if (eventName === "VideoProgress") {
        customData.progress = customData.progress || 0;
        customData.duration = customData.duration || 0;
        customData.current_time = customData.current_time || 0;
      }
      // Para Lead, garantir value/currency dinâmicos
      if (eventName === "Lead") {
        customData.value = typeof customData.value !== 'undefined' ? customData.value : 5000;
        customData.currency = customData.currency || "BRL";
      }

      // ✅ SEM PII: user_data apenas com dados técnicos e geo-enrichment
      const userData: any = {
        ...(externalId && { external_id: [externalId] }),
        client_ip_address: ip,
        client_user_agent: userAgent,
      };
      
      // Processamento robusto do FBP
      if (typeof event.user_data?.fbp === "string" && event.user_data.fbp.startsWith("fb.")) {
        const fbpPattern = /^fb\.[0-9]+\.[0-9]+\.[A-Za-z0-9_-]+$/;
        if (fbpPattern.test(event.user_data.fbp)) {
          userData.fbp = event.user_data.fbp;
          console.log('✅ FBP válido preservado:', event.user_data.fbp);
        } else {
          console.warn('⚠️ FBP formato inválido ignorado:', event.user_data.fbp);
        }
      }
      
      // ✅ CORREÇÃO: Processamento robusto do FBC usando a nova função
      if (event.user_data?.fbc) {
        const processedFbc = processFbc(event.user_data.fbc);
        if (processedFbc) {
          userData.fbc = processedFbc;
          console.log('✅ FBC processado e preservado:', processedFbc);
        }
      }
      
      // 🌍 GEO-ENRICHMENT: Preservar dados de geolocalização do frontend
      if (typeof event.user_data?.country === "string" && event.user_data.country.trim()) {
        userData.country = event.user_data.country.toLowerCase().trim();
        console.log('🌍 Country adicionado:', userData.country);
      }
      if (typeof event.user_data?.state === "string" && event.user_data.state.trim()) {
        userData.state = event.user_data.state.toLowerCase().trim();
        console.log('🌍 State adicionado:', userData.state);
      }
      if (typeof event.user_data?.city === "string" && event.user_data.city.trim()) {
        userData.city = event.user_data.city.toLowerCase().trim();
        console.log('🌍 City adicionado:', userData.city);
      }

      // ❌ REMOVIDO: Todo processamento de PII (email, phone, first_name, last_name)
      // Não coletamos mais esses dados no formulário

      return {
        event_name: eventName,
        event_id: eventId,
        event_time: eventTime,
        event_source_url: eventSourceUrl,
        action_source: actionSource,
        custom_data: customData,
        user_data: userData
      };
    });

    const payload = { data: enrichedData };
    const shouldCompress = Buffer.byteLength(JSON.stringify(payload)) > 2048;
    const body = shouldCompress ? zlib.gzipSync(JSON.stringify(payload)) : JSON.stringify(payload);
    const headers = {
      "Content-Type": "application/json",
      "Connection": "keep-alive",
      "User-Agent": "DigitalPaisagismo-CAPI-Proxy/1.0",
      ...(shouldCompress && { "Content-Encoding": "gzip" })
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    console.log("🔄 Enviando evento para Meta CAPI (SEM PII):", {
      events: enrichedData.length,
      event_names: enrichedData.map(e => e.event_name),
      has_pii: false, // ✅ Sempre false agora
      has_geo_data: enrichedData.some(e => e.user_data.country || e.user_data.state || e.user_data.city),
      geo_locations: enrichedData
        .filter(e => e.user_data.country)
        .map(e => `${e.user_data.country}/${e.user_data.state}/${e.user_data.city}`)
        .slice(0, 3),
      fbc_processed: enrichedData.filter(e => e.user_data.fbc).length
    });

    const response = await fetch(`${META_URL}?access_token=${ACCESS_TOKEN}`, {
      method: "POST",
      headers,
      body,
      signal: controller.signal
    });

    clearTimeout(timeout);
    const data = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      console.error("❌ Erro da Meta CAPI:", {
        status: response.status,
        data,
        events: enrichedData.length
      });

      return res.status(response.status).json({
        error: "Erro da Meta",
        details: data,
        processing_time_ms: responseTime
      });
    }

    console.log("✅ Evento enviado com sucesso para Meta CAPI:", {
      events_processed: enrichedData.length,
      processing_time_ms: responseTime,
      compression_used: shouldCompress
    });

    res.status(200).json({
      ...data
    });

  } catch (error: any) {
    console.error("❌ Erro no Proxy CAPI:", error);
    if (error.name === "AbortError") {
      return res.status(408).json({ error: "Timeout ao enviar evento para a Meta", timeout_ms: 8000 });
    }
    res.status(500).json({ error: "Erro interno no servidor CAPI." });
  }
}
