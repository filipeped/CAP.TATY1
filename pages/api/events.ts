// ✅ DIGITAL PAISAGISMO CAPI V6.3 - ULTRA OTIMIZADO
// Corrigido: fbclid preservado, geo-enrichment, cache inteligente, validação robusta

import type { NextApiRequest, NextApiResponse } from "next";
import crypto from "crypto";
import zlib from "zlib";

// Sistema de logging condicional otimizado
const isDevelopment = process.env.NODE_ENV === 'development';
const apiLogger = {
  log: (message: string, data?: any) => {
    if (isDevelopment) {
      console.log(message, data || '');
    }
  },
  warn: (message: string, data?: any) => {
    console.warn(message, data || '');
  },
  error: (message: string, data?: any) => {
    console.error(message, data || '');
  }
};

// Configurações da Meta CAPI
const PIXEL_ID = "765087775987515";
const ACCESS_TOKEN = "EAAQfmxkTTZCcBPHGbA2ojC29bVbNPa6GM3nxMxsZC29ijBmuyexVifaGnrjFZBZBS6LEkaR29X3tc5TWn4SHHffeXiPvexZAYKP5mTMoYGx5AoVYaluaqBTtiKIjWALxuMZAPVcBk1PuYCb0nJfhpzAezh018LU3cT45vuEflMicoQEHHk3H5YKNVAPaUZC6yzhcQZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

// ✅ CORREÇÃO CRÍTICA: Hash SHA256 sem .toLowerCase() para preservar fbclid
function hashSHA256(value: string): string | null {
  if (!value || typeof value !== 'string') {
    apiLogger.warn('⚠️ hashSHA256: Valor inválido:', value);
    return null;
  }
  
  try {
    return crypto.createHash("sha256")
      .update(
        value
          .trim()
          .normalize("NFD")
          .replace(/[\u0300-\u036f]/g, "") // Remove acentos
      )
      .digest("hex");
  } catch (error) {
    apiLogger.error('❌ Erro no hash SHA256:', error);
    return null;
  }
}

// ✅ GEO-ENRICHMENT: Função otimizada para obter localização via IP
async function getGeoLocation(ip: string) {
  try {
    // Validar IP antes de fazer a requisição
    if (!ip || ip === 'unknown' || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
      return null;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const response = await fetch(`https://ipapi.co/${ip}/json/`, {
      method: 'GET',
      headers: {
        'User-Agent': 'DigitalPaisagismo-GeoEnrich/1.0',
        'Accept': 'application/json'
      },
      signal: controller.signal
    });

    clearTimeout(timeout);

    if (!response.ok) {
      apiLogger.warn('⚠️ Geo API falhou:', response.status);
      return null;
    }

    const data = await response.json();
    
    // Validar se os dados são válidos
    if (data.error || !data.country_name) {
      apiLogger.warn('⚠️ Geo dados inválidos:', data.error || 'País não encontrado');
      return null;
    }

    const geoData = {
      country: data.country_name || data.country_code,
      state: data.region,
      city: data.city
    };

    apiLogger.log('🌍 Geo-enrichment sucesso:', {
      ip: ip.substring(0, 8) + '...',
      location: `${geoData.city}, ${geoData.state}, ${geoData.country}`
    });

    return geoData;
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      apiLogger.warn('⚠️ Geo-enrichment timeout (3s)');
    } else {
      apiLogger.warn('⚠️ Erro no geo-enrichment:', error instanceof Error ? error.message : 'Unknown error');
    }
    return null; // Falha silenciosa
  }
}

// Rate limiting otimizado
const RATE_LIMIT = 30;
const RATE_WINDOW_MS = 60000; // 1 minuto
const rateLimitMap = new Map<string, number[]>();

// Cache para geo-enrichment com limpeza automática
const geoCache = new Map<string, { data: any; timestamp: number }>();
const GEO_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 horas
const MAX_CACHE_SIZE = 100;

function rateLimit(ip: string): boolean {
  const now = Date.now();
  
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, []);
  }
  
  const timestamps = rateLimitMap.get(ip)!.filter((t: number) => now - t < RATE_WINDOW_MS);
  
  if (timestamps.length >= RATE_LIMIT) {
    return false;
  }
  
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  
  // Limpeza automática do rate limit map
  if (rateLimitMap.size > 1000) {
    const oldestKey = rateLimitMap.keys().next().value;
    rateLimitMap.delete(oldestKey);
  }
  
  return true;
}

// Função para validar FBP/FBC
function validateFacebookParam(param: string, type: 'fbp' | 'fbc'): boolean {
  if (!param || typeof param !== 'string') return false;
  return param.startsWith('fb.') && param.length > 10;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const startTime = Date.now();
  const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || 
             req.socket.remoteAddress || 
             "unknown";
  const userAgent = req.headers["user-agent"] || "";
  const origin = req.headers.origin;

  // ✅ CORS: Origens permitidas atualizadas
  const ALLOWED_ORIGINS = [
    "https://www.digitalpaisagismo.com",
    "https://digitalpaisagismo.com",
    "https://cap.digitalpaisagismo.com",
    "https://atendimento.digitalpaisagismo.com",
    "https://projeto.digitalpaisagismo.com",
    "https://www.projeto.digitalpaisagismo.com",
    "http://localhost:3000",
    "http://localhost:8080", // ✅ Adicionado para desenvolvimento
    "http://127.0.0.1:8080"
  ];

  // Headers de segurança e CORS
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin!) ? origin! : "https://www.digitalpaisagismo.com";
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

  // Preflight OPTIONS
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // Validação de método
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  // Rate limiting
  if (!rateLimit(ip)) {
    return res.status(429).json({ 
      error: "Limite de requisições excedido", 
      retry_after: 60,
      limit: RATE_LIMIT
    });
  }

  try {
    // Validação do payload
    if (!req.body?.data || !Array.isArray(req.body.data) || req.body.data.length === 0) {
      return res.status(400).json({ 
        error: "Payload inválido - campo 'data' obrigatório e deve ser um array não vazio" 
      });
    }

    // ✅ GEO-ENRICHMENT: Obter dados de localização com cache inteligente
    let geoData = null;
    const cacheKey = `geo_${ip}`;
    const cachedGeo = geoCache.get(cacheKey);
    
    if (cachedGeo && (Date.now() - cachedGeo.timestamp) < GEO_CACHE_TTL) {
      geoData = cachedGeo.data;
      apiLogger.log('🌍 Geo-enrichment (cache hit)');
    } else {
      geoData = await getGeoLocation(ip);
      if (geoData) {
        geoCache.set(cacheKey, {
          data: geoData,
          timestamp: Date.now()
        });
        
        // Limpeza automática do cache
        if (geoCache.size > MAX_CACHE_SIZE) {
          const oldestKey = geoCache.keys().next().value;
          geoCache.delete(oldestKey);
        }
      }
    }

    // ✅ PROCESSAMENTO DE EVENTOS: Enriquecimento e validação
    const enrichedData = req.body.data.map((event: any) => {
      // Session ID único
      let sessionId = event.session_id;
      if (!sessionId) {
        sessionId = req.cookies?.session_id || 
                   `sess_${Date.now()}_${Math.random().toString(36).substring(2, 12)}`;
      }

      // External ID baseado em email ou session
      let externalId = "";
      if (event.user_data?.email) {
        externalId = hashSHA256(event.user_data.email);
      } else if (sessionId) {
        externalId = hashSHA256(sessionId);
      }

      // Dados básicos do evento
      const eventId = event.event_id || `evt_${Date.now()}_${Math.random().toString(36).substring(2, 12)}`;
      const eventName = event.event_name || "Lead";
      const eventSourceUrl = event.event_source_url || origin || req.headers.referer || "https://www.digitalpaisagismo.com";
      const eventTime = event.event_time ? Math.floor(Number(event.event_time)) : Math.floor(Date.now() / 1000);
      const actionSource = event.action_source || "website";

      // ✅ CUSTOM DATA: Padronização por tipo de evento
      const customData = { ...event.custom_data };
      
      // Remover value/currency para eventos que não precisam
      if (["PageView", "ViewContent", "VideoProgress"].includes(eventName)) {
        delete customData.value;
        delete customData.currency;
      }
      
      // VideoProgress: garantir campos obrigatórios
      if (eventName === "VideoProgress") {
        customData.progress = Number(customData.progress) || 0;
        customData.duration = Number(customData.duration) || 0;
        customData.current_time = Number(customData.current_time) || 0;
      }
      
      // Lead: garantir value/currency
      if (eventName === "Lead") {
        customData.value = typeof customData.value !== 'undefined' ? Number(customData.value) : 5000;
        customData.currency = customData.currency || "BRL";
      }

      // ✅ USER DATA: Enriquecimento com geo-localização
      const userData: any = {
        client_ip_address: ip,
        client_user_agent: userAgent,
      };

      // External ID
      if (externalId) {
        userData.external_id = [externalId];
      }

      // Geo-enrichment
      if (geoData) {
        userData.country = geoData.country;
        userData.state = geoData.state;
        userData.city = geoData.city;
      }

      // ✅ FBP/FBC: Validação robusta
      if (validateFacebookParam(event.user_data?.fbp, 'fbp')) {
        userData.fbp = event.user_data.fbp;
      }
      if (validateFacebookParam(event.user_data?.fbc, 'fbc')) {
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

    // ✅ PAYLOAD: Preparação e compressão
    const payload = { data: enrichedData };
    const payloadSize = Buffer.byteLength(JSON.stringify(payload));
    const shouldCompress = payloadSize > 2048;
    const body = shouldCompress ? zlib.gzipSync(JSON.stringify(payload)) : JSON.stringify(payload);
    
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Connection": "keep-alive",
      "User-Agent": "DigitalPaisagismo-CAPI-Proxy/1.0",
    };
    
    if (shouldCompress) {
      headers["Content-Encoding"] = "gzip";
    }

    // ✅ ENVIO PARA META: Com timeout e controle de erro
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000); // 8s timeout

    apiLogger.log("🔄 Enviando para Meta CAPI:", {
      events: enrichedData.length,
      event_names: enrichedData.map(e => e.event_name),
      payload_size: `${Math.round(payloadSize / 1024)}KB`,
      compressed: shouldCompress,
      geo_enriched: !!geoData
    });

    const response = await fetch(`${META_URL}?access_token=${ACCESS_TOKEN}`, {
      method: "POST",
      headers,
      body,
      signal: controller.signal
    });

    clearTimeout(timeout);
    const responseData = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      apiLogger.error("❌ Erro da Meta CAPI:", {
        status: response.status,
        statusText: response.statusText,
        data: responseData,
        events: enrichedData.length,
        response_time: `${responseTime}ms`
      });

      return res.status(response.status).json({
        error: "Erro da Meta CAPI",
        details: responseData,
        processing_time_ms: responseTime,
        events_attempted: enrichedData.length
      });
    }

    // ✅ SUCESSO: Log e resposta
    apiLogger.log("✅ Sucesso Meta CAPI:", {
      events_processed: enrichedData.length,
      processing_time_ms: responseTime,
      compression_used: shouldCompress,
      geo_enriched: geoData ? `${geoData.city}, ${geoData.state}, ${geoData.country}` : 'N/A',
      events_received: responseData.events_received || 0
    });

    return res.status(200).json({
      ...responseData,
      processing_time_ms: responseTime,
      geo_enriched: geoData ? `${geoData.city}, ${geoData.state}, ${geoData.country}` : null,
      events_processed: enrichedData.length
    });

  } catch (error: any) {
    const responseTime = Date.now() - startTime;
    
    apiLogger.error("❌ Erro no Proxy CAPI:", {
      error: error.message,
      stack: error.stack,
      processing_time_ms: responseTime
    });
    
    if (error.name === "AbortError") {
      return res.status(408).json({ 
        error: "Timeout ao enviar evento para a Meta", 
        timeout_ms: 8000,
        processing_time_ms: responseTime
      });
    }
    
    return res.status(500).json({ 
      error: "Erro interno no servidor CAPI",
      processing_time_ms: responseTime
    });
  }
}
