require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const HOST = "0.0.0.0";

app.disable("x-powered-by");
app.set("trust proxy", 1);

const allowedOrigins = (process.env.FRONTEND_ORIGIN || "")
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin(origin, callback) {
    // Allow non-browser/server requests.
    if (!origin) return callback(null, true);
    if (allowedOrigins.length === 0) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("CORS origin not allowed"));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.use("/api", generalLimiter);

const JWT_SECRET = process.env.JWT_SECRET || "";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || "";

let pool = null;
if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === "false" ? false : { rejectUnauthorized: false }
  });
}

async function initDb() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS reports (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT,
      content JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

function requireJwt(req, res, next) {
  if (!JWT_SECRET) {
    return res.status(503).json({
      ok: false,
      error: "Authentication is not configured on the server."
    });
  }

  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, error: "Missing bearer token." });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ ok: false, error: "Invalid or expired token." });
  }
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidUrl(value) {
  try {
    const u = new URL(value);
    return ["http:", "https:"].includes(u.protocol);
  } catch {
    return false;
  }
}

function analyzeMessageLocally(text) {
  const s = String(text || "").toLowerCase();
  const rules = [
    { terms: ["password", "كلمة المرور", "كلمه المرور"], points: 22, reason: "طلب بيانات تسجيل الدخول أو كلمة المرور." },
    { terms: ["otp", "verification code", "رمز التحقق", "كود التحقق"], points: 20, reason: "طلب رمز تحقق حساس." },
    { terms: ["click", "اضغط", "ادخل", "رابط", "link"], points: 12, reason: "وجود توجيه لفتح رابط أو تنفيذ إجراء سريع." },
    { terms: ["urgent", "immediately", "عاجل", "فوراً", "حالاً"], points: 14, reason: "استخدام ضغط أو استعجال لاتخاذ القرار." },
    { terms: ["bank", "بنك", "حساب بنكي", "بطاقة"], points: 14, reason: "الإشارة إلى حساب أو خدمة مالية." },
    { terms: ["money", "payment", "transfer", "تحويل", "دفع", "أموال"], points: 12, reason: "طلب أو ادعاء متعلق بالمال أو التحويلات." },
    { terms: ["crypto", "bitcoin", "usdt", "عملة رقمية"], points: 10, reason: "الإشارة إلى أصول أو تحويلات رقمية." },
    { terms: ["gift", "prize", "ربحت", "جائزة", "مكافأة"], points: 10, reason: "وعد بجائزة أو مكافأة قد يكون طُعمًا للتصيد." }
  ];

  const reasons = [];
  let score = 0;

  for (const rule of rules) {
    if (rule.terms.some(term => s.includes(term))) {
      score += rule.points;
      reasons.push(rule.reason);
    }
  }

  score = Math.min(100, score);
  const level = score >= 70 ? "high" : score >= 40 ? "medium" : "low";

  return {
    score,
    level,
    reasons,
    recommendation:
      level === "high"
        ? "لا تضغط الروابط ولا ترسل رموز التحقق أو كلمات المرور. تحقق من الجهة عبر موقعها الرسمي."
        : level === "medium"
          ? "تعامل بحذر، ولا تنفذ أي طلب حساس قبل التحقق من المرسل والجهة الرسمية."
          : "لا توجد مؤشرات قوية في النص وحده، لكن لا تعتمد على التحليل الآلي وحده."
  };
}

async function geminiGenerate(prompt) {
  if (!GEMINI_API_KEY) {
    throw new Error("GEMINI_API_KEY is not configured.");
  }

  const endpoint =
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 1200
      }
    })
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data?.error?.message || `Gemini request failed (${response.status}).`);
  }

  return (data?.candidates?.[0]?.content?.parts || [])
    .map(p => p.text || "")
    .join("")
    .trim();
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "Digital Protection Backend",
    version: "1.0.0",
    status: "online",
    endpoints: ["/health", "/api/config/status", "/api/ai/chat", "/api/ai/analyze-message", "/api/links/scan", "/api/auth/register", "/api/auth/login", "/api/reports"]
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    status: "healthy",
    service: "digital-protection-backend",
    time: new Date().toISOString(),
    databaseConfigured: Boolean(pool)
  });
});

app.get("/api/config/status", (req, res) => {
  res.json({
    ok: true,
    ai: {
      provider: "Google Gemini",
      configured: Boolean(GEMINI_API_KEY),
      model: GEMINI_MODEL
    },
    virusTotal: { configured: Boolean(VIRUSTOTAL_API_KEY) },
    database: { configured: Boolean(pool) },
    authentication: { configured: Boolean(JWT_SECRET) }
  });
});

app.post("/api/ai/chat", aiLimiter, async (req, res) => {
  const message = String(req.body?.message || "").trim();
  if (!message) return res.status(400).json({ ok: false, error: "message is required." });
  if (message.length > 12000) return res.status(413).json({ ok: false, error: "Message is too long." });

  try {
    const reply = await geminiGenerate(
      `أنت مساعد داخل منصة "حمايتي الرقمية". أجب بالعربية بشكل طبيعي وواضح، ولا تدّعي أنك جهة حكومية أو محامٍ أو خبير جنائي. إذا كان السؤال متعلقًا بالأمن الرقمي، قدم خطوات آمنة وعملية. لا تطلب كلمات المرور أو رموز التحقق أو مفاتيح API من المستخدم.\n\nرسالة المستخدم:\n${message}`
    );
    res.json({ ok: true, provider: "gemini", reply });
  } catch (error) {
    res.status(503).json({ ok: false, error: error.message });
  }
});

app.post("/api/ai/analyze-message", aiLimiter, async (req, res) => {
  const message = String(req.body?.message || "").trim();
  if (!message) return res.status(400).json({ ok: false, error: "message is required." });
  if (message.length > 20000) return res.status(413).json({ ok: false, error: "Message is too long." });

  const local = analyzeMessageLocally(message);

  if (!GEMINI_API_KEY) {
    return res.json({ ok: true, mode: "local", analysis: local });
  }

  try {
    const prompt = `حلل الرسالة التالية من منظور السلامة الرقمية فقط.
أعد JSON صالحًا فقط بالمفاتيح:
score (0-100), level (low|medium|high), reasons (array of strings), recommendation (string).
لا تخترع حقائق عن المرسل ولا تعتبر التحليل دليلاً قانونيًا.
الرسالة:
${message}`;

    const aiText = await geminiGenerate(prompt);
    let parsed;
    try {
      parsed = JSON.parse(aiText.replace(/^```json\s*/i, "").replace(/```$/i, "").trim());
    } catch {
      parsed = local;
    }

    res.json({
      ok: true,
      mode: "gemini+local",
      analysis: {
        score: Math.max(0, Math.min(100, Number(parsed.score) || local.score)),
        level: ["low", "medium", "high"].includes(parsed.level) ? parsed.level : local.level,
        reasons: Array.isArray(parsed.reasons) ? parsed.reasons.slice(0, 12) : local.reasons,
        recommendation: String(parsed.recommendation || local.recommendation)
      }
    });
  } catch {
    res.json({ ok: true, mode: "local-fallback", analysis: local });
  }
});

app.post("/api/links/scan", aiLimiter, async (req, res) => {
  const url = String(req.body?.url || "").trim();
  if (!isValidUrl(url)) {
    return res.status(400).json({ ok: false, error: "A valid http/https URL is required." });
  }
  if (!VIRUSTOTAL_API_KEY) {
    return res.status(503).json({
      ok: false,
      error: "VIRUSTOTAL_API_KEY is not configured.",
      setup: "Add VIRUSTOTAL_API_KEY to Render Environment Variables."
    });
  }

  try {
    const form = new URLSearchParams();
    form.set("url", url);

    const submit = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
      },
      body: form
    });

    const submitted = await submit.json().catch(() => ({}));
    if (!submit.ok) {
      return res.status(submit.status).json({
        ok: false,
        error: submitted?.error?.message || "VirusTotal submission failed."
      });
    }

    const analysisId = submitted?.data?.id;
    if (!analysisId) return res.status(502).json({ ok: false, error: "VirusTotal returned no analysis id." });

    // VirusTotal analysis IDs returned for URL submissions can be polled after submission.
    let analysis = null;
    for (let i = 0; i < 4; i++) {
      await new Promise(r => setTimeout(r, i === 0 ? 1500 : 2500));
      const r = await fetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`, {
        headers: { "x-apikey": VIRUSTOTAL_API_KEY }
      });
      const d = await r.json().catch(() => ({}));
      if (r.ok) {
        analysis = d;
        if (d?.data?.attributes?.status === "completed") break;
      }
    }

    res.json({
      ok: true,
      provider: "VirusTotal",
      url,
      analysisId,
      status: analysis?.data?.attributes?.status || "queued",
      stats: analysis?.data?.attributes?.stats || null,
      analysisUrl: `https://www.virustotal.com/gui/url/${analysisId}`
    });
  } catch (error) {
    res.status(502).json({ ok: false, error: error.message });
  }
});

app.post("/api/auth/register", async (req, res) => {
  if (!pool || !JWT_SECRET) {
    return res.status(503).json({ ok: false, error: "Database/authentication is not configured." });
  }

  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || "");

  if (!isValidEmail(email)) return res.status(400).json({ ok: false, error: "Invalid email." });
  if (password.length < 10) return res.status(400).json({ ok: false, error: "Password must be at least 10 characters." });

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users(email, password_hash) VALUES($1,$2) RETURNING id,email,created_at",
      [email, hash]
    );
    const user = result.rows[0];
    const token = jwt.sign({ sub: String(user.id), email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.status(201).json({ ok: true, user, token });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ ok: false, error: "Email already registered." });
    res.status(500).json({ ok: false, error: "Registration failed." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  if (!pool || !JWT_SECRET) {
    return res.status(503).json({ ok: false, error: "Database/authentication is not configured." });
  }

  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || "");

  try {
    const result = await pool.query("SELECT id,email,password_hash,created_at FROM users WHERE email=$1", [email]);
    if (!result.rows[0]) return res.status(401).json({ ok: false, error: "Invalid email or password." });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ ok: false, error: "Invalid email or password." });

    const token = jwt.sign({ sub: String(user.id), email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({
      ok: true,
      user: { id: user.id, email: user.email, created_at: user.created_at },
      token
    });
  } catch {
    res.status(500).json({ ok: false, error: "Login failed." });
  }
});

app.get("/api/reports", requireJwt, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false, error: "Database is not configured." });

  const result = await pool.query(
    "SELECT id,type,title,content,created_at FROM reports WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100",
    [Number(req.user.sub)]
  );
  res.json({ ok: true, reports: result.rows });
});

app.post("/api/reports", requireJwt, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false, error: "Database is not configured." });

  const type = String(req.body?.type || "general").slice(0, 80);
  const title = String(req.body?.title || "").slice(0, 200);
  const content = req.body?.content && typeof req.body.content === "object" ? req.body.content : {};

  const result = await pool.query(
    "INSERT INTO reports(user_id,type,title,content) VALUES($1,$2,$3,$4) RETURNING id,type,title,content,created_at",
    [Number(req.user.sub), type, title, JSON.stringify(content)]
  );

  res.status(201).json({ ok: true, report: result.rows[0] });
});

app.use((req, res) => {
  res.status(404).json({ ok: false, error: "Endpoint not found." });
});

app.use((err, req, res, next) => {
  console.error(err);
  if (err.message === "CORS origin not allowed") {
    return res.status(403).json({ ok: false, error: "CORS origin not allowed." });
  }
  res.status(500).json({ ok: false, error: "Internal server error." });
});

initDb()
  .then(() => {
    app.listen(PORT, HOST, () => {
      console.log(`Digital Protection Backend listening on ${HOST}:${PORT}`);
    });
  })
  .catch(error => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
