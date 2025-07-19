import type { NextApiRequest, NextApiResponse } from "next";
import crypto from "crypto";
import zlib from "zlib";

const PIXEL_ID = "1267249108110418";
const ACCESS_TOKEN = "EAAQfmxkTTZCcBPMUBbdZAnJ2UpFgpDNfGs7phoz4iU0CT8G7St4HS3TOmRpDlLSG3oEky1sYiVZAkDmBRdsYgrZCgWP99N9wZAhSqPYwZAGxqPZBhAGVYuIDSnYQ9LtGwccWyitNNd1VfraGmvf2vZBETtLwlTdCKaEjYhIq0lZAfHRynUnbIZB8RptANoTwUhdgZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

function hashSHA256(value: string) {
  if (!value || typeof value !== 'string') return null;
  return crypto.createHash("sha256")
    .update(
      value.trim().toLowerCase()
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
    )
    .digest("hex");
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const startTime = Date.now();
  const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
  const userAgent = req.headers["user-agent"] || "";
  const origin = req.headers.origin;

  const ALLOWED_ORIGINS = [
    "https://www.digitalpaisagismo.com",
    "https://digitalpaisagismo.com",
    "https://cap.digitalpaisagismo.com",
    "https://atendimento.digitalpaisagismo.com",
    "https://projeto.digitalpaisagismo.com",
    "http://localhost:3000"
  ];

  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGINS.includes(origin!) ? origin! : "https://www.digitalpaisagismo.com");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });

  try {
    if (!req.body?.data || !Array.isArray(req.body.data)) {
      return res.status(400).json({ error: "Payload inválido - campo 'data' obrigatório" });
    }

    const enrichedData = req.body.data.map((event: any) => {
      const sessionId = event.session_id || "";
      const externalId = sessionId ? hashSHA256(sessionId) : "";
      const eventId = event.event_id || `evt_${Date.now()}_${Math.random().toString(36).substr(2, 10)}`;
      const eventName = event.event_name || "Lead";
      const eventSourceUrl = event.event_source_url || origin || req.headers.referer || "https://www.digitalpaisagismo.com";
      const eventTime = event.event_time || Math.floor(Date.now() / 1000);
      const actionSource = event.action_source || "website";

      const customData = { ...event.custom_data };
      // Só remove value/currency de eventos comportamentais
      if (["PageView", "ViewContent", "VideoProgress"].includes(eventName)) {
        delete customData.value;
        delete customData.currency;
      }

      return {
        event_name: eventName,
        event_id: eventId,
        event_time: eventTime,
        event_source_url: eventSourceUrl,
        action_source: actionSource,
        custom_data: customData,
        user_data: {
          ...(externalId && { external_id: [externalId] }),
          client_ip_address: ip,
          client_user_agent: userAgent,
          ...(typeof event.user_data?.fbp === "string" && event.user_data.fbp.startsWith("fb.") && { fbp: event.user_data.fbp }),
          ...(typeof event.user_data?.fbc === "string" && event.user_data.fbc.startsWith("fb.") && { fbc: event.user_data.fbc })
        }
      };
    });

    const payload = { data: enrichedData };
    const shouldCompress = Buffer.byteLength(JSON.stringify(payload)) > 2048;
    const body = shouldCompress ? zlib.gzipSync(JSON.stringify(payload)) : JSON.stringify(payload);
    const headers = {
      "Content-Type": "application/json",
      ...(shouldCompress && { "Content-Encoding": "gzip" })
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

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
      console.error("❌ Erro da Meta CAPI:", data);
      return res.status(response.status).json({ error: "Erro da Meta", details: data });
    }

    console.log("✅ Evento enviado com sucesso:", {
      events: enrichedData.length,
      time_ms: responseTime,
      compressed: shouldCompress
    });

    res.status(200).json({
      ...data,
      proxy_metadata: {
        processing_time_ms: responseTime,
        events_processed: enrichedData.length,
        compression_used: shouldCompress,
        timestamp: new Date().toISOString(),
        pii_processed: false
      }
    });
  } catch (error: any) {
    console.error("❌ Erro interno no Proxy CAPI:", error);
    if (error.name === "AbortError") {
      return res.status(408).json({ error: "Timeout ao enviar evento para a Meta", timeout_ms: 8000 });
    }
    res.status(500).json({ error: "Erro interno no servidor CAPI." });
  }
}
