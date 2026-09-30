import { getStore } from "@netlify/blobs";
import { createHmac, timingSafeEqual } from "node:crypto";

const sign = (exp) => createHmac("sha256", process.env.ADMIN_PASSWORD).update(String(exp)).digest("hex");
const same = (x, y) => { const a = Buffer.from(x), b = Buffer.from(y); return a.length === b.length && timingSafeEqual(a, b); };
const authed = (req) => {
  const [exp, sig] = (req.headers.get("authorization") || "").replace("Bearer ", "").split(".");
  return !!(exp && sig && Date.now() < Number(exp) && same(sig, sign(exp)));
};

export default async (req) => {
  const path = new URL(req.url).pathname;
  if (!process.env.ADMIN_PASSWORD) return new Response("Falta la variable ADMIN_PASSWORD", { status: 500 });
  const store = getStore("cbd");

  if (path === "/api/login" && req.method === "POST") {
    const { password } = await req.json().catch(() => ({}));
    if (!same(String(password || ""), process.env.ADMIN_PASSWORD)) return new Response("No", { status: 401 });
    const exp = Date.now() + 12 * 3600e3;
    return Response.json({ token: exp + "." + sign(exp) });
  }
  if (path === "/api/content") {
    if (req.method === "GET") {
      const data = (await store.get("content", { type: "json" })) || {};
      return Response.json(data, { headers: { "cache-control": "no-store" } });
    }
    if (req.method === "POST") {
      if (!authed(req)) return new Response("No", { status: 401 });
      await store.setJSON("content", await req.json());
      return Response.json({ ok: true });
    }
  }
  return new Response("No encontrado", { status: 404 });
};

export const config = { path: ["/api/login", "/api/content"] };
