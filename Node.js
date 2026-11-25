
require("dotenv").config();

const express = require("express");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "2mb" }));
app.use(express.static("."));

app.use("/api/", rateLimit({
  windowMs: 60000,
  limit: 100
}));

const db = new Database("database.sqlite");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const RELAY_SECRET = process.env.RELAY_SECRET;

if (!JWT_SECRET || !ADMIN_PASSWORD || !RELAY_SECRET) {
  throw new Error("Konfigurasi secret server belum lengkap");
}

db.exec(`
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1,
  owner_id TEXT
);

CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  plan TEXT NOT NULL,
  amount INTEGER NOT NULL,
  status TEXT DEFAULT 'PENDING',
  created_at INTEGER NOT NULL,
  issued_key TEXT,
  buyer_note TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  username TEXT,
  connected INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS game_state (
  host_id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS participants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS auctions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id TEXT NOT NULL,
  status TEXT DEFAULT 'BELUM DIMULAI',
  duration INTEGER DEFAULT 60,
  started_at INTEGER,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS gift_events (
  event_id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL,
  sender TEXT NOT NULL,
  gift_name TEXT NOT NULL,
  quantity INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL
);
`);

const plans = {
  "3hari": {
    name: "KEY 3 HARI",
    price: 5000,
    duration: 3 * 86400000
  },
  "7hari": {
    name: "KEY 7 HARI",
    price: 10000,
    duration: 7 * 86400000
  },
  "30hari": {
    name: "KEY 30 HARI",
    price: 40000,
    duration: 30 * 86400000
  },
  "permanen": {
    name: "KEY PERMANEN",
    price: 100000,
    duration: null
  }
};

function hashKey(key) {
  return crypto.createHash("sha256")
    .update(key)
    .digest("hex");
}

function generateKey() {
  return "ZANN-" +
    crypto.randomBytes(4).toString("hex").toUpperCase() +
    "-" +
    crypto.randomBytes(4).toString("hex").toUpperCase();
}

function createKey(plan) {
  if (!plans[plan]) {
    throw new Error("Paket tidak valid");
  }

  const key = generateKey();

  const expiresAt = plans[plan].duration
    ? Date.now() + plans[plan].duration
    : null;

  db.prepare(`
    INSERT INTO keys
    (key_hash, plan, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `).run(
    hashKey(key),
    plan,
    expiresAt,
    Date.now()
  );

  return key;
}

function createToken(data) {
  return jwt.sign(data, JWT_SECRET, {
    expiresIn: "12h"
  });
}

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "")
      .replace(/^Bearer\s+/i, "");

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;
    next();
  } catch {
    res.status(401).json({
      error: "Silakan login kembali"
    });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      error: "Akses admin ditolak"
    });
  }

  next();
}

function licenseCheck(req, res, next) {
  if (req.user.role === "admin") {
    return next();
  }

  const license = db.prepare(`
    SELECT * FROM keys WHERE key_hash = ?
  `).get(req.user.keyHash);

  if (!license || !license.active) {
    return res.status(403).json({
      error: "KEY tidak aktif"
    });
  }

  if (
    license.expires_at !== null &&
    Date.now() >= license.expires_at
  ) {
    return res.status(403).json({
      error: "KEY KEDALUWARSA. Akses game dihentikan."
    });
  }

  next();
}

function hostOwner(req, res, next) {
  const host = db.prepare(`
    SELECT * FROM hosts
    WHERE id = ? AND user_id = ?
  `).get(req.params.id, req.user.id);

  if (!host) {
    return res.status(404).json({
      error: "Host tidak ditemukan"
    });
  }

  req.host = host;
  next();
}

// LANDING / PAKET

app.get("/api/plans", (req, res) => {
  res.json(plans);
});

// BUAT TRANSAKSI

app.post("/api/purchase", (req, res) => {
  const { plan } = req.body;
  const selected = plans[plan];

  if (!selected) {
    return res.status(400).json({
      error: "Paket tidak tersedia"
    });
  }

  const id = "ZVIP-" +
    crypto.randomBytes(6).toString("hex").toUpperCase();

  db.prepare(`
    INSERT INTO transactions
    (id, plan, amount, created_at)
    VALUES (?, ?, ?, ?)
  `).run(
    id,
    plan,
    selected.price,
    Date.now()
  );

  res.json({
    success: true,
    transaction: id,
    package: selected.name,
    amount: selected.price,
    payment: process.env.PAYMENT_NUMBER,
    instructions:
      "Transfer manual sesuai nominal. Simpan nomor transaksi dan hubungi admin untuk pemeriksaan pembayaran.",
    status: "MENUNGGU PEMBAYARAN"
  });
});

// CEK TRANSAKSI

app.get("/api/transaction/:id", (req, res) => {
  const transaction = db.prepare(`
    SELECT id, plan, amount, status, created_at
    FROM transactions WHERE id = ?
  `).get(req.params.id);

  if (!transaction) {
    return res.status(404).json({
      error: "Transaksi tidak ditemukan"
    });
  }

  res.json(transaction);
});

// LOGIN KEY

app.post("/api/login", (req, res) => {
  const { key } = req.body;

  if (!key || typeof key !== "string") {
    return res.status(400).json({
      error: "Masukkan KEY"
    });
  }

  const license = db.prepare(`
    SELECT * FROM keys WHERE key_hash = ?
  `).get(hashKey(key.trim().toUpperCase()));

  if (!license || !license.active) {
    return res.status(401).json({
      error: "KEY tidak valid atau dinonaktifkan"
    });
  }

  if (
    license.expires_at !== null &&
    Date.now() >= license.expires_at
  ) {
    return res.status(403).json({
      error: "KEY sudah kedaluwarsa"
    });
  }

  if (license.used && license.owner_id) {
    return res.status(403).json({
      error: "KEY sudah digunakan"
    });
  }

  const userId = crypto.randomUUID();

  db.prepare(`
    UPDATE keys SET used = 1, owner_id = ?
    WHERE id = ?
  `).run(userId, license.id);

  const token = createToken({
    id: userId,
    role: "user",
    keyHash: license.key_hash
  });

  res.json({
    success: true,
    token,
    plan: license.plan,
    expiresAt: license.expires_at
  });
});

// ADMIN LOGIN

app.post("/api/admin/login", async (req, res) => {
  const { password } = req.body;

  if (
    typeof password !== "string" ||
    password.length > 200
  ) {
    return res.status(400).json({
      error: "Password tidak valid"
    });
  }

  const valid = await bcrypt.compare(
    password,
    await bcrypt.hash(ADMIN_PASSWORD, 10)
  );

  if (!valid) {
    return res.status(401).json({
      error: "Password admin salah"
    });
  }

  res.json({
    success: true,
    token: createToken({
      id: "main-admin",
      role: "admin"
    })
  });
});

// ADMIN MEMBUAT KEY GRATIS

app.post(
  "/api/admin/keys",
  auth,
  adminOnly,
  (req, res) => {
    const { plan } = req.body;

    if (!plans[plan]) {
      return res.status(400).json({
        error: "Paket tidak valid"
      });
    }

    const key = createKey(plan);

    res.json({
      success: true,
      key,
      plan
    });
  }
);

// ADMIN MELIHAT TRANSAKSI

app.get(
  "/api/admin/transactions",
  auth,
  adminOnly,
  (req, res) => {
    const rows = db.prepare(`
      SELECT id, plan, amount, status, created_at
      FROM transactions
      ORDER BY created_at DESC
    `).all();

    res.json(rows);
  }
);

// ADMIN MENYETUJUI PEMBAYARAN
// HANYA SETELAH MEMERIKSA UANG BENAR-BENAR DITERIMA.

app.post(
  "/api/admin/transactions/:id/approve",
  auth,
  adminOnly,
  (req, res) => {
    const tx = db.prepare(`
      SELECT * FROM transactions WHERE id = ?
    `).get(req.params.id);

    if (!tx) {
      return res.status(404).json({
        error: "Transaksi tidak ditemukan"
      });
    }

    if (tx.status === "BERHASIL") {
      return res.status(409).json({
        error: "Transaksi sudah diproses"
      });
    }

    if (tx.status !== "PENDING") {
      return res.status(409).json({
        error: "Status transaksi tidak dapat disetujui"
      });
    }

    const key = createKey(tx.plan);

    db.prepare(`
      UPDATE transactions
      SET status = 'BERHASIL', issued_key = ?
      WHERE id = ? AND status = 'PENDING'
    `).run(key, tx.id);

    res.json({
      success: true,
      transaction: tx.id,
      key
    });
  }
);

// ADMIN MEMBATALKAN KEY

app.post(
  "/api/admin/keys/:hash/disable",
  auth,
  adminOnly,
  (req, res) => {
    db.prepare(`
      UPDATE keys SET active = 0
      WHERE key_hash = ?
    `).run(req.params.hash);

    res.json({ success: true });
  }
);

// HOST BARU

app.post(
  "/api/hosts",
  auth,
  licenseCheck,
  (req, res) => {
    const id = crypto.randomUUID();

    db.prepare(`
      INSERT INTO hosts (id, user_id, created_at)
      VALUES (?, ?, ?)
    `).run(id, req.user.id, Date.now());

    db.prepare(`
      INSERT INTO game_state (host_id, state)
      VALUES (?, ?)
    `).run(id, JSON.stringify({
      participants: [],
      locked: false,
      timerEnd: null,
      auction: {
        status: "BELUM DIMULAI",
        duration: 60
      }
    }));

    res.json({
      success: true,
      id
    });
  }
);

// DAFTAR HOST MILIK SENDIRI

app.get(
  "/api/hosts",
  auth,
  licenseCheck,
  (req, res) => {
    const hosts = db.prepare(`
      SELECT id, username, connected
      FROM hosts WHERE user_id = ?
    `).all(req.user.id);

    res.json(hosts);
  }
);

// CONNECT HOST

app.post(
  "/api/hosts/:id/connect",
  auth,
  licenseCheck,
  hostOwner,
  (req, res) => {
    const { username } = req.body;

    if (
      typeof username !== "string" ||
      !/^[a-zA-Z0-9._]{2,24}$/.test(username)
    ) {
      return res.status(400).json({
        error: "Username TikTok tidak valid"
      });
    }

    // Belum menyatakan LIVE tersambung.
    // Koneksi baru aktif setelah adapter provider
    // TikTok LIVE yang sah memberikan konfirmasi.

    res.json({
      success: false,
      connected: false,
      status: "PROVIDER BELUM DIKONFIGURASI",
      message: "Integrasikan adapter TikTok LIVE terlebih dahulu."
    });
  }
);

// DISCONNECT HOST

app.post(
  "/api/hosts/:id/disconnect",
  auth,
  licenseCheck,
  hostOwner,
  (req, res) => {
    db.prepare(`
      UPDATE hosts SET connected = 0
      WHERE id = ?
    `).run(req.params.id);

    io.to(req.params.id).emit("host-disconnected");

    res.json({
      success: true,
      connected: false
    });
  }
);

// TAMBAH PESERTA

app.post(
  "/api/hosts/:id/participants",
  auth,
  licenseCheck,
  hostOwner,
  (req, res) => {
    const { name } = req.body;

    if (
      typeof name !== "string" ||
      !name.trim() ||
      name.length > 50
    ) {
      return res.status(400).json({
        error: "Nama peserta tidak valid"
      });
    }

    const state = JSON.parse(
      db.prepare(`
        SELECT state FROM game_state
        WHERE host_id = ?
      `).get(req.host.id).state
    );

    if (state.locked && state.timerEnd &&
        Date.now() >= state.timerEnd) {
      return res.status(403).json({
        error: "Waktu habis. Peserta tidak dapat bergabung."
      });
    }

    db.prepare(`
      INSERT INTO participants
      (host_id, name, created_at)
      VALUES (?, ?, ?)
    `).run(req.host.id, name.trim(), Date.now());

    io.to(req.host.id).emit("participant-added", {
      name: name.trim()
    });

    res.json({ success: true });
  }
);

// DAFTAR PESERTA

app.get(
  "/api/hosts/:id/participants",
  auth,
  licenseCheck,
  hostOwner,
  (req, res) => {
    const rows = db.prepare(`
      SELECT id, name, created_at
      FROM participants
      WHERE host_id = ?
      ORDER BY id DESC
    `).all(req.host.id);

    res.json(rows);
  }
);

// HAPUS PESERTA

app.delete(
  "/api/hosts/:id/participants/:participantId",
  auth,
  licenseCheck,
  hostOwner,
  (req, res) => {
    db.prepare(`
      DELETE FROM participants
      WHERE id = ? AND host_id = ?
    `).run(
      req.params.participantId,
      req.host.id
    );

    res.json({ success: true });
  }
);

// RESET PESERTA

app.delete(
  "/api/hosts/:id/participants",
  auth,
  licenseCheck,
  hostOwner,
  (req, res) => {
    db.prepare(`
      DELETE FROM participants WHERE host_id = ?
    `).run(req.host.id);

    res.json({ success: true });
  }
);

// TIMER ELIMINASI

app.post(
  "/api/hosts/:id/timer",
  auth,
  licenseCheck,
  hostOwner,
  (req, res) => {
    const { seconds, mode } = req.body;

    if (
      !Number.isInteger(seconds) ||
      seconds < 0 ||
      seconds > 86400 ||
      !["LOCKED", "NO_LOCKED"].includes(mode)
    ) {
      return res.status(400).json({
        error: "Pengaturan timer tidak valid"
      });
    }

    const state = JSON.parse(
      db.prepare(`
        SELECT state FROM game_state WHERE host_id = ?
      `).get(req.host.id).state
    );

    state.locked = mode === "LOCKED";
    state.timerEnd = seconds
      ? Date.now() + seconds * 1000
      : null;

    db.prepare(`
      UPDATE game_state SET state = ?
      WHERE host_id = ?
    `).run(JSON.stringify(state), req.host.id);

    res.json({
      success: true,
      timerEnd: state.timerEnd,
      mode
    });
  }
);

// PENGATURAN LELANG

app.post(
  "/api/hosts/:id/auction",
  auth,
  licenseCheck,
  hostOwner,
  (req, res) => {
    const { action, duration } = req.body;

    if (action === "start") {
      if (
        !Number.isInteger(duration) ||
        duration < 1 ||
        duration > 86400
      ) {
        return res.status(400).json({
          error: "Durasi lelang tidak valid"
        });
      }

      const startedAt = Date.now();

      db.prepare(`
        INSERT INTO auctions
        (host_id, status, duration, started_at)
        VALUES (?, 'BERLANGSUNG', ?, ?)
      `).run(req.host.id, duration, startedAt);

      return res.json({
        success: true,
        status: "BERLANGSUNG",
        endsAt: startedAt + duration * 1000
      });
    }

    if (action === "reset") {
      db.prepare(`
        UPDATE auctions SET status = 'SELESAI'
        WHERE host_id = ? AND status = 'BERLANGSUNG'
      `).run(req.host.id);

      return res.json({
        success: true,
        status: "SELESAI"
      });
    }

    res.status(400).json({
      error: "Aksi lelang tidak valid"
    });
  }
);

// RELAY: HANYA ADMIN

app.post(
  "/api/admin/relay",
  auth,
  adminOnly,
  (req, res) => {
    const { enabled } = req.body;

    if (typeof enabled !== "boolean") {
      return res.status(400).json({
        error: "Status relay tidak valid"
      });
    }

    // Relay pusat diaktifkan oleh admin.
    global.relayEnabled = enabled;

    io.emit("relay-status", {
      enabled
    });

    res.json({
      success: true,
      enabled
    });
  }
);

// RELAY WEBHOOK
// Hanya event dari provider yang telah diautentikasi.

app.post("/api/relay/event", (req, res) => {
  const secret = req.headers["x-relay-secret"];

  if (
    !global.relayEnabled ||
    !secret ||
    secret !== RELAY_SECRET
  ) {
    return res.status(403).json({
      error: "Relay tidak aktif atau akses ditolak"
    });
  }

  const {
    eventId,
    hostId,
    sender,
    giftName,
    quantity
  } = req.body;

  if (
    !eventId || !hostId ||
    typeof sender !== "string" ||
    typeof giftName !== "string" ||
    !Number.isInteger(quantity) ||
    quantity < 1
  ) {
    return res.status(400).json({
      error: "Event tidak valid"
    });
  }

  const host = db.prepare(`
    SELECT id, connected FROM hosts WHERE id = ?
  `).get(hostId);

  if (!host || !host.connected) {
    return res.status(404).json({
      error: "Host tidak aktif"
    });
  }

  try {
    db.prepare(`
      INSERT INTO gift_events
      (event_id, host_id, sender, gift_name, quantity, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      eventId,
      hostId,
      sender,
      giftName,
      quantity,
      Date.now()
    );
  } catch {
    return res.status(409).json({
      error: "Event gift sudah pernah diterima"
    });
  }

  // Gift hanya masuk ke host tujuan.
  for (let i = 0; i < quantity; i++) {
    db.prepare(`
      INSERT INTO participants
      (host_id, name, created_at)
      VALUES (?, ?, ?)
    `).run(hostId, sender, Date.now());
  }

  io.to(hostId).emit("gift-received", {
    sender,
    giftName,
    quantity
  });

  res.json({ success: true });
});

io.on("connection", socket => {
  socket.on("join-host", data => {
    if (typeof data?.hostId === "string") {
      socket.join(data.hostId);
    }
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    application: "ZANN ELIMINASI VIP",
    server: "ONLINE",
    relay: Boolean(global.relayEnabled)
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log("ZANN ELIMINASI VIP berjalan di port " + PORT);
});
