// ✅ DIGITAL PAISAGISMO CAPI V6.2 - COMPLETO E OTIMIZADO
// Corrigido: normalização de acentos, arrays para user_data, validação robusta FBP/FBC

import type { NextApiRequest, NextApiResponse } from "next";
import crypto from "crypto";
import zlib from "zlib";

// Sistema de logging condicional para API
const isDevelopment = process.env.NODE_ENV === 'development';
const apiLogger = {
  log: (message: string, data?: any) => {
    if (isDevelopment) {
      if (data) {
        console.log(message, data);
      } else {
        console.log(message);
      }
    }
  },
  warn: (message: string, data?: any) => {
    if (data) {
      console.warn(message, data);
    } else {
      console.warn(message);
    }
  },
  error: (message: string, data?: any) => {
    if (data) {
      console.error(message, data);
    } else {
      console.error(message);
    }
  }
};

const PIXEL_ID = "765087775987515";
const ACCESS_TOKEN = "EAAQfmxkTTZCcBPHGbA2ojC29bVbNPa6GM3nxMxsZC29ijBmuyexVifaGnrjFZBZBS6LEkaR29X3tc5TWn4SHHffeXiPvexZAYKP5mTMoYGx5AoVYaluaqBTtiKIjWALxuMZAPVcBk1PuYCb0nJfhpzAezh018LU3cT45vuEflMicoQEHHk3H5YKNVAPaUZC6yzhcQZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

// ✅ CORREÇÃO CRÍTICA: Normalização de acentos para nomes brasileiros
// ✅ FBCLID FIX: Removido .toLowerCase() para preservar fbclid original
function hashSHA256(value: string) {
  if (!value || typeof value !== 'string') {
    apiLogger.warn('⚠️ hashSHA256: Valor inválido:', value);
    return null;
  }
  return crypto.createHash("sha256")
    .update(
      value
        .trim()
        .normalize("NFD")
        .replace(/[ -\u036f]/g, "") // Remove acentos
    )
    .digest("hex");
}

// ✅ GEO-ENRICHMENT: Função para obter localização via IP
async function getGeoLocation(ip: string) {
  try {
    // Validar IP antes de fazer a requisição
    if (!ip || ip === 'unknown' || ip === '127.0.0.1' || ip === '::1') {
      return null;
    }

    const response = await fetch(`https://ipapi.co/${ip}/json/`, {
      method: 'GET',
      headers: {
        'User-Agent': 'DigitalPaisagismo-GeoEnrich/1.0'
      },
      signal: AbortSignal.timeout(3000) // Timeout de 3s para geo-enrichment
    });

    if (!response.ok) {
      apiLogger.warn('⚠️ Geo API falhou:', response.status);
      return null;
    }

    const data = await response.json();
    
    // Validar se os dados são válidos
    if (data.error || !data.country_name) {
      apiLogger.warn('⚠️ Geo dados inválidos:', data);
      return null;
    }

    const geoData = {
      country: data.country_name || data.country_code,
      state: data.region,
      city: data.city
    };

    apiLogger.log('🌍 Geo-enrichment sucesso:', {
      ip: ip.substring(0, 8) + '...',
      country: geoData.country,
      state: geoData.state,
      city: geoData.city
    });

    return geoData;
  } catch (error) {
    apiLogger.warn('⚠️ Erro no geo-enrichment:', error instanceof Error ? error.message : 'Unknown error');
    return null; // Falha silenciosa
  }
}

const RATE_LIMIT = 30;
const rateLimitMap = new Map();

// Cache para geo-enrichment (evitar requests duplicados)
const geoCache = new Map();
const GEO_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 horas

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

    // ✅ GEO-ENRICHMENT: Obter dados de localização com cache
    let geoData = null;
    const cacheKey = `geo_${ip}`;
    const cachedGeo = geoCache.get(cacheKey);
    
    if (cachedGeo && (Date.now() - cachedGeo.timestamp) < GEO_CACHE_TTL) {
      geoData = cachedGeo.data;
      apiLogger.log('🌍 Geo-enrichment (cache):', geoData);
    } else {
      geoData = await getGeoLocation(ip);
      if (geoData) {
        geoCache.set(cacheKey, {
          data: geoData,
          timestamp: Date.now()
        });
        
        // Limpar cache antigo (manter apenas 100 entradas)
        if (geoCache.size > 100) {
          const oldestKey = geoCache.keys().next().value;
          geoCache.delete(oldestKey);
        }
      }
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
      let externalId = "";
      if (event.user_data?.email) {
        externalId = hashSHA256(event.user_data.email);
      } else if (sessionId) {
        externalId = hashSHA256(sessionId);
      }
      const eventId = event.event_id || `evt_${Date.now()}_${Math.random().toString(36).substr(2, 10)}`;
      const eventName = event.event_name || "Lead";
      // Novo: event_source_url dinâmico
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

      // ✅ GEO-ENRICHMENT: Padronizar user_data com dados de localização
      const userData: any = {
        ...(externalId && { external_id: [externalId] }),
        client_ip_address: ip,
        client_user_agent: userAgent,
        ...(geoData && {
          country: geoData.country,
          state: geoData.state,
          city: geoData.city
        }),
      };
      if (typeof event.user_data?.fbp === "string" && event.user_data.fbp.startsWith("fb.")) {
        userData.fbp = event.user_data.fbp;
      }
      if (typeof event.user_data?.fbc === "string" && event.user_data.fbc.startsWith("fb.")) {
        userData.fbc = event.user_data.fbc;
      }

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
    const timeout = setTimeout(() => controller.abort(), 5000);

    apiLogger.log("🔄 Enviando evento para Meta CAPI:", {
      events: enrichedData.length,
      event_names: enrichedData.map(e => e.event_name),
      has_pii: enrichedData.some(e => e.user_data.em || e.user_data.ph || e.user_data.fn || e.user_data.ln)
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
      apiLogger.error("❌ Erro da Meta CAPI:", {
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

    apiLogger.log("✅ Evento enviado com sucesso para Meta CAPI:", {
      events_processed: enrichedData.length,
      processing_time_ms: responseTime,
      compression_used: shouldCompress,
      geo_enriched: geoData ? `${geoData.city}, ${geoData.state}, ${geoData.country}` : 'N/A'
    });

    res.status(200).json({
      ...data,
      geo_enriched: geoData ? `${geoData.city}, ${geoData.state}, ${geoData.country}` : null
    });

  } catch (error: any) {
    apiLogger.error("❌ Erro no Proxy CAPI:", error);
    if (error.name === "AbortError") {
      return res.status(408).json({ error: "Timeout ao enviar evento para a Meta", timeout_ms: 5000 });
    }
    res.status(500).json({ error: "Erro interno no servidor CAPI." });
  }
}
