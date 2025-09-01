// ✅ PERSONAL TATY SCHAPUIS CAPI V8.1 - DEDUPLICAÇÃO CORRIGIDA
// CORREÇÃO CRÍTICA: Event_id agora é consistente entre pixel e API
// PROBLEMA IDENTIFICADO: Event_ids aleatórios impediam deduplicação correta
// SOLUÇÃO: Event_ids determinísticos baseados em dados do evento
// IMPORTANTE: Frontend deve enviar event_id único para cada evento
// TTL otimizado para 6h para reduzir eventos fantasma
// Cache aumentado para 50k eventos para melhor cobertura

import type { NextApiRequest, NextApiResponse } from "next";
import crypto from "crypto";
import zlib from "zlib";

const PIXEL_ID = "1406446857128984";
const ACCESS_TOKEN = "EAALIy2dZAggsBPfaDSZBLNqUXZAG7fI1ovKKZBuFDDB1qtXdZAnyFYGlIkOZAKieaJcs1UzSqlp58MpHQMVR2QtJb4vmfARiyZBz0VGWpxtZCLTq3O7VZCAOWARWgm6Ddp8moSZAodNoBnNkv4ZBH5YDcQZBp2eLZCZCKjB7JeLtlgZCPUZA27ZA7KUtXiW7ZCdOq9sLHikQZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

// ✅ SISTEMA DE DEDUPLICAÇÃO MELHORADO
const eventCache = new Map<string, number>();
const CACHE_TTL = 6 * 60 * 60 * 1000; // 6 horas (otimizado para reduzir eventos fantasma)
const MAX_CACHE_SIZE = 50000; // Aumentado para suportar mais eventos

function isDuplicateEvent(eventId: string): boolean {
  const now = Date.now();

  // Limpeza automática de eventos expirados (sem for...of)
  let cleanedCount = 0;
  eventCache.forEach((timestamp, id) => {
    if (now - timestamp > CACHE_TTL) {
      eventCache.delete(id);
      cleanedCount++;
    }
  });

  if (cleanedCount > 0) {
    console.log(`🧹 Cache limpo: ${cleanedCount} eventos expirados removidos (TTL: 6h)`);
  }

  // Verificar se é duplicata
  if (eventCache.has(eventId)) {
    const lastSeen = eventCache.get(eventId);
    const timeDiff = now - (lastSeen || 0);
    console.warn(`🚫 Evento duplicado bloqueado: ${eventId} (última ocorrência: ${Math.round(timeDiff/1000)}s atrás)`);
    return true;
  }

  // Controle de tamanho do cache
  if (eventCache.size >= MAX_CACHE_SIZE) {
    // Remove 10% do cache quando atingir o limite para melhor performance
    const itemsToRemove = Math.floor(MAX_CACHE_SIZE * 0.1);
    let removedCount = 0;
    
    for (const [eventId] of eventCache) {
      if (removedCount >= itemsToRemove) break;
      eventCache.delete(eventId);
      removedCount++;
    }
    
    console.log(`🗑️ Cache overflow: ${removedCount} eventos mais antigos removidos (${eventCache.size}/${MAX_CACHE_SIZE})`);
  }

  // Adicionar ao cache
  eventCache.set(eventId, now);
  console.log(`✅ Evento adicionado ao cache de deduplicação: ${eventId} (cache size: ${eventCache.size})`);
  return false;
}

// ✅ MELHORADO: Hash SHA256 com fallback robusto
function hashSHA256(value: string): string {
  if (!value || typeof value !== "string") {
    console.warn("⚠️ hashSHA256: Valor inválido, usando fallback:", value);
    return crypto.createHash("sha256").update(`fallback_${Date.now()}_${Math.random()}`).digest("hex");
  }
  return crypto.createHash("sha256").update(value.trim()).digest("hex");
}

// ✅ IPv6 INTELIGENTE: Detecção e validação de IP com prioridade IPv6
function getClientIP(
  req: NextApiRequest
): { ip: string; type: "IPv4" | "IPv6" | "unknown" } {
  const ipSources = [
    req.headers["cf-connecting-ip"],
    req.headers["x-real-ip"],
    req.headers["x-forwarded-for"],
    req.headers["x-client-ip"],
    req.headers["x-cluster-client-ip"],
    req.socket?.remoteAddress,
  ];

  const candidateIPs: string[] = [];
  ipSources.forEach((source) => {
    if (!source) return;
    if (typeof source === "string") {
      const ips = source.split(",").map((ip) => ip.trim());
      candidateIPs.push(...ips);
    }
  });

  function isValidIPv4(ip: string): boolean {
    const ipv4Regex =
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
  }

  function isValidIPv6(ip: string): boolean {
    const cleanIP = ip.replace(/^\[|\]$/g, "");
    // ✅ REGEX IPv6 OTIMIZADA: Mais eficiente e simples
    try {
      // Validação básica de formato IPv6
      if (!/^[0-9a-fA-F:]+$/.test(cleanIP.replace(/\./g, ''))) return false;
      
      // Usar URL constructor para validação nativa (mais eficiente)
      new URL(`http://[${cleanIP}]`);
      return true;
    } catch {
      // Fallback para regex simplificada
      const ipv6Simple = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|^::1$|^::$/;
      return ipv6Simple.test(cleanIP);
    }
  }

  function isPrivateIP(ip: string): boolean {
    if (isValidIPv4(ip)) {
      const parts = ip.split(".").map(Number);
      // Validar se todas as partes são números válidos
      if (parts.some(part => isNaN(part) || part < 0 || part > 255)) {
        return false;
      }
      return (
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168) ||
        parts[0] === 127
      );
    }
    if (isValidIPv6(ip)) {
      const cleanIP = ip.replace(/^\[|\]$/g, "");
      return (
        cleanIP === "::1" ||
        cleanIP.startsWith("fe80:") ||
        cleanIP.startsWith("fc00:") ||
        cleanIP.startsWith("fd00:")
      );
    }
    return false;
  }

  const validIPv6: string[] = [];
  const validIPv4: string[] = [];

  candidateIPs.forEach((ip) => {
    if (isValidIPv6(ip) && !isPrivateIP(ip)) validIPv6.push(ip);
    else if (isValidIPv4(ip) && !isPrivateIP(ip)) validIPv4.push(ip);
  });

  // ✅ PRIORIDADE IPv6: Garantir que a Meta reconheça corretamente o IPv6
  if (validIPv6.length > 0) {
    const selectedIP = validIPv6[0];
    console.log("🌐 IPv6 detectado (prioridade para Meta CAPI):", selectedIP);
    return { ip: selectedIP, type: "IPv6" };
  }
  if (validIPv4.length > 0) {
    const selectedIP = validIPv4[0];
    console.log("🌐 IPv4 detectado (fallback):", selectedIP);
    return { ip: selectedIP, type: "IPv4" };
  }

  const fallbackIP = candidateIPs[0] || "unknown";
  console.warn("⚠️ IP não identificado, usando fallback:", fallbackIP);
  return { ip: fallbackIP, type: "unknown" };
}

// ✅ NOVA FUNÇÃO: Processamento robusto do FBC
function processFbc(fbc: string): string | null {
  if (!fbc || typeof fbc !== "string") {
    console.warn("⚠️ FBC inválido:", fbc);
    return null;
  }

  const trimmedFbc = fbc.trim();

  const fbcPattern = /^fb\.1\.[0-9]+\.[A-Za-z0-9_-]+$/;
  if (fbcPattern.test(trimmedFbc)) {
    console.log("✅ FBC válido (formato padrão):", trimmedFbc);
    return trimmedFbc;
  }

  const fbclidPattern = /^[A-Za-z0-9_-]+$/;
  if (fbclidPattern.test(trimmedFbc)) {
    const timestamp = Math.floor(Date.now() / 1000);
    const formattedFbc = `fb.1.${timestamp}.${trimmedFbc}`;
    console.log("✅ FBC formatado de fbclid puro:", formattedFbc);
    return formattedFbc;
  }

  if (trimmedFbc.startsWith("fbclid=")) {
    const fbclid = trimmedFbc.substring(7);
    if (fbclidPattern.test(fbclid)) {
      const timestamp = Math.floor(Date.now() / 1000);
      const formattedFbc = `fb.1.${timestamp}.${fbclid}`;
      console.log("✅ FBC formatado de fbclid com prefixo:", formattedFbc);
      return formattedFbc;
    }
  }

  console.warn("⚠️ FBC formato inválido:", trimmedFbc);
  return null;
}

const RATE_LIMIT = 100; // Aumentado para suportar picos de tráfego
const rateLimitMap = new Map<string, number[]>();

function rateLimit(ip: string): boolean {
  const now = Date.now();
  const windowMs = 60000;
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const timestamps = (rateLimitMap.get(ip) || []).filter((t) => now - t < windowMs);
  if (timestamps.length >= RATE_LIMIT) return false;
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  if (rateLimitMap.size > 1000) {
    const oldest = rateLimitMap.keys().next();
    if (!oldest.done) rateLimitMap.delete(oldest.value);
  }
  return true;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const startTime = Date.now();

  const { ip, type: ipType } = getClientIP(req);
  const userAgent = (req.headers["user-agent"] as string) || "";
  const origin = (req.headers.origin as string) || "";

  const ALLOWED_ORIGINS = [
    "http://personaltatyschapuis.com",
    "https://personaltatyschapuis.com",
    "https://www.personaltatyschapuis.com",
    "http://localhost:3000",
    "http://localhost:8080",
    "http://localhost:8081",
  ];

  res.setHeader(
    "Access-Control-Allow-Origin",
    ALLOWED_ORIGINS.includes(origin) ? origin : "http://personaltatyschapuis.com"
  );
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

    // 🛡️ FILTRO DE DEDUPLICAÇÃO MELHORADO: Verificar duplicatas antes do processamento
    const originalCount = req.body.data.length;
    // ✅ CORRIGIDO: Priorizar event_id do frontend para consistência Pixel/CAPI
    const eventsWithIds = req.body.data.map((event: any) => {
      if (!event.event_id) {
        // Gerar event_id determinístico apenas como fallback
        const eventName = event.event_name || "Lead";
        const eventTime = event.event_time && !isNaN(Number(event.event_time)) ? Math.floor(Number(event.event_time)) : Math.floor(Date.now() / 1000);
        const externalId = event.user_data?.external_id || "no_ext_id";
        const eventSourceUrl =
        event.event_source_url || origin || (req.headers.referer as string) || "http://personaltatyschapuis.com";
        const eventData = `${eventName}_${eventTime}_${externalId}_${eventSourceUrl}`;
        event.event_id = `evt_${hashSHA256(eventData).substring(0, 16)}`;
        console.warn("⚠️ Event_id gerado no servidor (fallback) - deve vir do frontend:", event.event_id);
      } else {
        console.log("✅ Event_id recebido do frontend (consistência Pixel/CAPI):", event.event_id);
      }
      return event;
    });
    
    // Segundo passo: filtrar duplicatas usando os event_ids
    const filteredData = eventsWithIds.filter((event: any) => {
      return !isDuplicateEvent(event.event_id);
    });

    const duplicatesBlocked = originalCount - filteredData.length;

    if (duplicatesBlocked > 0) {
      console.log(
        `🛡️ Deduplicação: ${duplicatesBlocked} eventos duplicados bloqueados de ${originalCount}`
      );
    }

    if (filteredData.length === 0) {
      return res.status(200).json({
        message: "Todos os eventos foram filtrados como duplicatas",
        duplicates_blocked: duplicatesBlocked,
        original_count: originalCount,
        cache_size: eventCache.size,
      });
    }

    const enrichedData = filteredData.map((event: any) => {
      let externalId = event.user_data?.external_id || null;

      if (!externalId) {
        let sessionId = event.session_id;
        if (!sessionId) {
          const anyReq = req as any;
          if (anyReq.cookies && anyReq.cookies.session_id) {
            sessionId = anyReq.cookies.session_id;
          } else {
            sessionId = `sess_${Date.now()}_${crypto.randomUUID().replace(/-/g, '').substring(0, 12)}`;
          }
        }
        externalId = sessionId ? hashSHA256(sessionId) : null;
        console.log("⚠️ External_id gerado no servidor (fallback):", externalId);
      } else {
        console.log("✅ External_id recebido do frontend (SHA256):", externalId);
      }

      const eventName = event.event_name || "Lead";
      const eventSourceUrl =
        event.event_source_url || origin || (req.headers.referer as string) || "http://personaltatyschapuis.com";
      const eventTime = event.event_time && !isNaN(Number(event.event_time)) ? Math.floor(Number(event.event_time)) : Math.floor(Date.now() / 1000);
      
      // ✅ Event_id já foi definido na etapa de deduplicação
      const eventId = event.event_id;
      console.log("✅ Event_id processado:", eventId);
      const actionSource = event.action_source || "website";

      const customData: Record<string, any> = { ...(event.custom_data || {}) };
      if (eventName === "PageView") {
        delete customData.value;
        delete customData.currency;
      }
      if (eventName === "Lead") {
        customData.value = typeof customData.value !== "undefined" ? customData.value : 5000;
        customData.currency = customData.currency || "BRL";
      }

      const userData: any = {
        ...(externalId && { external_id: externalId }),
        client_ip_address: ip,
        client_user_agent: userAgent,
      };

      if (typeof event.user_data?.fbp === "string" && event.user_data.fbp.startsWith("fb.")) {
        const fbpPattern = /^fb\.[0-9]+\.[0-9]+\.[A-Za-z0-9_-]+$/;
        if (fbpPattern.test(event.user_data.fbp)) {
          userData.fbp = event.user_data.fbp;
          console.log("✅ FBP válido preservado:", event.user_data.fbp);
        } else {
          console.warn("⚠️ FBP formato inválido ignorado:", event.user_data.fbp);
        }
      }

      if (event.user_data?.fbc) {
        const processedFbc = processFbc(event.user_data.fbc);
        if (processedFbc) {
          userData.fbc = processedFbc;
          console.log("✅ FBC processado e preservado:", processedFbc);
        }
      }

      if (typeof event.user_data?.country === "string" && event.user_data.country.trim()) {
        userData.country = event.user_data.country.toLowerCase().trim();
        console.log("🌍 Country adicionado:", userData.country);
      }
      if (typeof event.user_data?.state === "string" && event.user_data.state.trim()) {
        userData.state = event.user_data.state.toLowerCase().trim();
        console.log("🌍 State adicionado:", userData.state);
      }
      if (typeof event.user_data?.city === "string" && event.user_data.city.trim()) {
        userData.city = event.user_data.city.toLowerCase().trim();
        console.log("🌍 City adicionado:", userData.city);
      }

      return {
        event_name: eventName,
        event_id: eventId,
        event_time: eventTime,
        event_source_url: eventSourceUrl,
        action_source: actionSource,
        custom_data: customData,
        user_data: userData,
      };
    });

    const payload = { data: enrichedData };
    const jsonPayload = JSON.stringify(payload);
    const shouldCompress = Buffer.byteLength(jsonPayload) > 2048;
    const body = shouldCompress ? zlib.gzipSync(jsonPayload) : jsonPayload;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Connection: "keep-alive",
      "User-Agent": "PersonalTatySchapuis-CAPI-Proxy/1.0",
      ...(shouldCompress ? { "Content-Encoding": "gzip" } : {}),
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000); // Aumentado para 15s

    console.log("🔄 Enviando evento para Meta CAPI (DEDUPLICAÇÃO CORRIGIDA):", {
      events: enrichedData.length,
      original_events: originalCount,
      duplicates_blocked: duplicatesBlocked,
      deduplication_rate: `${Math.round((duplicatesBlocked / originalCount) * 100)}%`,
      event_names: enrichedData.map((e) => e.event_name),
      event_ids: enrichedData.map((e) => e.event_id).slice(0, 3), // Primeiros 3 para debug
      ip_type: ipType,
      client_ip: ip,
      has_pii: false,
      external_ids_count: enrichedData.filter((e) => e.user_data.external_id).length,
      external_ids_from_frontend: enrichedData.filter(
        (e) => e.user_data.external_id && e.user_data.external_id.length === 64
      ).length,
      has_geo_data: enrichedData.some((e) => e.user_data.country || e.user_data.state || e.user_data.city),
      geo_locations: enrichedData
        .filter((e) => e.user_data.country)
        .map((e) => `${e.user_data.country}/${e.user_data.state}/${e.user_data.city}`)
        .slice(0, 3),
      fbc_processed: enrichedData.filter((e) => e.user_data.fbc).length,
      cache_size: eventCache.size,
      cache_ttl_hours: CACHE_TTL / (60 * 60 * 1000),
    });

    const response = await fetch(`${META_URL}?access_token=${ACCESS_TOKEN}`, {
      method: "POST",
      headers,
      body: body as any,
      signal: controller.signal,
    });

    clearTimeout(timeout);
    const data = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      console.error("❌ Erro da Meta CAPI:", {
        status: response.status,
        data,
        events: enrichedData.length,
        ip_type: ipType,
        duplicates_blocked: duplicatesBlocked,
      });

      return res.status(response.status).json({
        error: "Erro da Meta",
        details: data,
        processing_time_ms: responseTime,
      });
    }

    console.log("✅ Evento enviado com sucesso para Meta CAPI:", {
      events_processed: enrichedData.length,
      duplicates_blocked: duplicatesBlocked,
      processing_time_ms: responseTime,
      compression_used: shouldCompress,
      ip_type: ipType,
      external_ids_sent: enrichedData.filter((e) => e.user_data.external_id).length,
      sha256_format_count: enrichedData.filter(
        (e) => e.user_data.external_id && e.user_data.external_id.length === 64
      ).length,
      cache_size: eventCache.size,
    });

    res.status(200).json({
      ...data,
      ip_info: { type: ipType, address: ip },
      deduplication_info: {
        original_events: originalCount,
        processed_events: enrichedData.length,
        duplicates_blocked: duplicatesBlocked,
        cache_size: eventCache.size,
      },
    });
  } catch (error: any) {
    console.error("❌ Erro no Proxy CAPI:", error);
    if (error?.name === "AbortError") {
      return res
        .status(408)
        .json({ error: "Timeout ao enviar evento para a Meta", timeout_ms: 15000 });
    }
    res.status(500).json({ error: "Erro interno no servidor CAPI." });
  }
}
