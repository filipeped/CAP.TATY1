// /pages/api/events.ts

// ✅ PERSONAL TATYSCHAPUIS CAPI V8.0 - IPv6 OTIMIZADO + DEDUPLICAÇÃO
// Removido: normalização de acentos e eventos de vídeo
// Adicionado: detecção inteligente IPv6 com fallback IPv4
// Adicionado: sistema de deduplicação de eventos
// Ajuste: removido for...of em Map.entries() (compatível com targets antigos)

import type { NextApiRequest, NextApiResponse } from "next";
import crypto from "crypto";
import zlib from "zlib";

const PIXEL_ID = "1406446857128984";
const ACCESS_TOKEN = "EAALIy2dZAggsBPfyle5Gf2pfKehpACDintxED7A850eJKa7PUhPuxE1SX2VeRDPpCctiCOJOdduBcAcMVLKhkDZC4ZBpNtwmIWih0PLYZBOtfhUnUNBkzDFJWjGBF2hxGnZBpFyLPoV1ZCajryfGt9V2agToq8kXPVFlQwRXhYEiS0pk9EOOZBXxsmdxRWcNwZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

// ✅ SISTEMA DE DEDUPLICAÇÃO
const eventCache = new Map<string, number>();
const CACHE_TTL = 5 * 60 * 1000;
const MAX_CACHE_SIZE = 10000;

function isDuplicateEvent(eventId: string): boolean {
  const now = Date.now();
  let cleanedCount = 0;
  eventCache.forEach((timestamp, id) => {
    if (now - timestamp > CACHE_TTL) {
      eventCache.delete(id);
      cleanedCount++;
    }
  });
  if (cleanedCount > 0) console.log(`🧹 Cache limpo: ${cleanedCount} eventos expirados removidos`);
  if (eventCache.has(eventId)) {
    console.warn("🚫 Evento duplicado bloqueado:", eventId);
    return true;
  }
  if (eventCache.size >= MAX_CACHE_SIZE) {
    const oldest = eventCache.keys().next();
    if (!oldest.done) {
      eventCache.delete(oldest.value);
      console.log("🗑️ Cache cheio: evento mais antigo removido");
    }
  }
  eventCache.set(eventId, now);
  return false;
}

// ✅ HASH SHA256
function hashSHA256(value: string): string | null {
  if (!value || typeof value !== "string") return null;
  return crypto.createHash("sha256").update(value.trim()).digest("hex");
}

// ✅ IP DETECTOR
function getClientIP(req: NextApiRequest): { ip: string; type: "IPv4" | "IPv6" | "unknown" } {
  const ipSources = [
    req.headers["cf-connecting-ip"],
    req.headers["x-real-ip"],
    req.headers["x-forwarded-for"],
    req.socket?.remoteAddress,
  ];
  const candidateIPs: string[] = [];
  ipSources.forEach((source) => {
    if (typeof source === "string") candidateIPs.push(...source.split(",").map((ip) => ip.trim()));
  });
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  const validIPv6 = candidateIPs.filter((ip) => ipv6Regex.test(ip));
  const validIPv4 = candidateIPs.filter((ip) => ipv4Regex.test(ip));
  if (validIPv6.length > 0) return { ip: validIPv6[0], type: "IPv6" };
  if (validIPv4.length > 0) return { ip: validIPv4[0], type: "IPv4" };
  return { ip: candidateIPs[0] || "unknown", type: "unknown" };
}

// ✅ PROCESSAMENTO DE FBC
function processFbc(fbc: string): string | null {
  if (!fbc || typeof fbc !== "string") return null;
  const trimmedFbc = fbc.trim();
  if (/^fb\.1\.[0-9]+\.[A-Za-z0-9_-]+$/.test(trimmedFbc)) return trimmedFbc;
  if (/^[A-Za-z0-9_-]+$/.test(trimmedFbc)) return `fb.1.${Math.floor(Date.now() / 1000)}.${trimmedFbc}`;
  if (trimmedFbc.startsWith("fbclid=")) {
    const fbclid = trimmedFbc.substring(7);
    if (/^[A-Za-z0-9_-]+$/.test(fbclid)) return `fb.1.${Math.floor(Date.now() / 1000)}.${fbclid}`;
  }
  return null;
}

const RATE_LIMIT = 30;
const rateLimitMap = new Map<string, number[]>();
function rateLimit(ip: string): boolean {
  const now = Date.now();
  const windowMs = 60000;
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const timestamps = (rateLimitMap.get(ip) || []).filter((t) => now - t < windowMs);
  if (timestamps.length >= RATE_LIMIT) return false;
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  return true;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { ip, type: ipType } = getClientIP(req);
  const userAgent = (req.headers["user-agent"] as string) || "";
  const origin = (req.headers.origin as string) || "";

  const ALLOWED_ORIGINS = [
    "https://www.personaltatyschapuis.com",
    "https://personaltatyschapuis.com",
    "http://localhost:3000",
    "http://localhost:8080",
  ];

  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGINS.includes(origin) ? origin : "https://www.personaltatyschapuis.com");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });
  if (!rateLimit(ip)) return res.status(429).json({ error: "Limite de requisições excedido", retry_after: 60 });

  try {
    const data = req.body?.data;
    if (!data || !Array.isArray(data)) return res.status(400).json({ error: "Payload inválido" });

    const filteredData = data.filter((event: any) => !isDuplicateEvent(event.event_id || `evt_${Date.now()}`));
    const enrichedData = filteredData.map((event: any) => {
      const eventId = event.event_id || `evt_${Date.now()}`;
      const externalId = event.user_data?.external_id || hashSHA256(event.session_id || `sess_${Date.now()}`);
      return {
        ...event,
        event_id: eventId,
        user_data: {
          ...(event.user_data || {}),
          external_id: externalId,
          client_ip_address: ip,
          client_user_agent: userAgent,
        },
      };
    });

    const payload = { data: enrichedData };
    const jsonPayload = JSON.stringify(payload);
    const body = Buffer.byteLength(jsonPayload) > 2048 ? zlib.gzipSync(jsonPayload) : jsonPayload;

    const response = await fetch(`${META_URL}?access_token=${ACCESS_TOKEN}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body as any,
    });
    const result = await response.json();
    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({ error: "Erro interno no servidor CAPI." });
  }
}


