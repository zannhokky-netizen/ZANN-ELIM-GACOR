
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("./database");

const app = express();

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: "100kb" }));
app.use(express.static("public"));

app.use(session({
  name: "zann.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 12 * 60 * 60 * 1000
  }
}));

app.use("/api", rateLimit({
  windowMs: 60 * 1000,
  limit: 100
}));

const now = () => Date.now();

const plans = {
  "3": {
    name: "3 HARI",
    days: 3,
    price: 5000
  },
  "7": {
    name: "7 HARI",
    days: 7,
    price: 10000
  },
  "30": {
    name: "30 HARI",
    days: 30,
    price: 40000
  },
  "permanent": {
    name: "PERMANEN",
    days: null,
    price: 100000
  }
};

function makeKey() {
  return "ZANN-" +
    crypto.randomBytes(16).toString("hex").toUpperCase();
}

function adminOnly(req, res, next) {
  if (req.session.role !== "ADMIN") {
    return res.status(403).json({
      error: "AKSES ADMIN DITOLAK"
    });
  }
  next();
}

function userOnly(req, res, next) {
  if (!req.session.keyId) {
    return res.status(401).json({
      error: "SILAKAN LOGIN MENGGUNAKAN KEY"
    });
  }

  const key = db.prepare(
    "SELECT * FROM keys_table WHERE id=?"
  ).get(req.session.keyId);

  if (!key || key.status !== "ACTIVE") {
    req.session.destroy(() => {});
    return res.status(401).json({
      error: "KEY TIDAK AKTIF"
    });
  }

  if (key.expires_at && key.expires_at <= now()) {
    db.prepare(
      "UPDATE keys_table SET status='EXPIRED' WHERE id=?"
    ).run(key.id);

    req.session.destroy(() => {});

    return res.status(403).json({
      error: "MASA BERLAKU KEY HABIS. AKSES GAME DIHENTIKAN."
    });
  }

  req.key = key;
  next();
}

function hostAccess(req, res, next) {
  const host = db.prepare(`
    SELECT * FROM hosts
    WHERE id=? AND owner_key=?
  `).get(req.params.hostId, req.key.key_code);

  if (!host) {
    return res.status(404).json({
      error: "HOST TIDAK DITEMUKAN"
    });
  }

  req.host = host;
  next();
}

// ===============================
// STORE
// ===============================

app.get("/api/store", (req, res) => {
  res.json({
    name: "ZANN ELIMINASI VIP",
    plans
  });
});

app.post("/api/checkout", (req, res) => {
  const { plan, quantity } = req.body;

  const selected = plans[plan];
  const count = Number(quantity);

  if (!selected ||
      !Number.isInteger(count) ||
      count < 1 ||
      count > 100) {
    return res.status(400).json({
      error: "PILIH PAKET DAN JUMLAH KEY YANG VALID"
    });
  }

  const amount = selected.price * count;

  const id = "ZVIP-" +
    crypto.randomBytes(6).toString("hex").toUpperCase();

  db.prepare(`
    INSERT INTO transactions
    (id, quantity, plan, amount, payment_number, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    id,
    count,
    plan,
    amount,
    process.env.PAYMENT_NUMBER,
    now()
  );

  res.json({
    success: true,
    transaction: {
      id,
      quantity: count,
      plan: selected.name,
      price_per_key: selected.price,
      amount,
      payment_number: process.env.PAYMENT_NUMBER,
      status: "PENDING"
    },
    message: "Silakan lakukan pembayaran dan tunggu verifikasi admin."
  });
});

// ===============================
// CEK TRANSAKSI
// ===============================

app.get("/api/transaction/:id", (req, res) => {
  const tx = db.prepare(`
    SELECT id, quantity, plan, amount,
    status, created_at
    FROM transactions WHERE id=?
  `).get(req.params.id);

  if (!tx) {
    return res.status(404).json({
      error: "TRANSAKSI TIDAK DITEMUKAN"
    });
  }

  if (req.session.role !== "ADMIN" &&
      req.session.transactionId !== tx.id) {
    return res.status(403).json({
      error: "AKSES DITOLAK"
    });
  }

  const issuedKeys = tx.issued
    ? db.prepare(`
        SELECT key_code FROM keys_table
        WHERE created_at >= ?
      `).all(tx.created_at)
    : [];

  res.json({
    ...tx,
    keys: issuedKeys
  });
});

// ===============================
// ADMIN LOGIN
// ===============================

app.post("/api/admin/login", async (req, res) => {
  const { password } = req.body;

  if (!password || !process.env.ADMIN_PASSWORD_HASH) {
    return res.status(400).json({
      error: "KONFIGURASI ADMIN BELUM LENGKAP"
    });
  }

  const valid = await bcrypt.compare(
    password,
    process.env.ADMIN_PASSWORD_HASH
  );

  if (!valid) {
    return res.status(401).json({
      error: "PASSWORD SALAH"
    });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).end();

    req.session.role = "ADMIN";

    res.json({
      success: true,
      message: "ADMIN LOGIN BERHASIL"
    });
  });
});

// ===============================
// ADMIN MEMBUAT KEY GRATIS
// ===============================

app.post("/api/admin/create-key",
  adminOnly,
  (req, res) => {

    const { plan, quantity } = req.body;
    const selected = plans[plan];
    const count = Number(quantity);

    if (!selected ||
        !Number.isInteger(count) ||
        count < 1 ||
        count > 1000) {
      return res.status(400).json({
        error: "DATA KEY TIDAK VALID"
      });
    }

    const create = db.transaction(() => {
      const result = [];

      for (let i = 0; i < count; i++) {
        const code = makeKey();

        db.prepare(`
          INSERT INTO keys_table
          (key_code, plan, duration_days, created_at)
          VALUES (?, ?, ?, ?)
        `).run(
          code,
          plan,
          selected.days,
          now()
        );

        result.push(code);
      }

      return result;
    });

    res.json({
      success: true,
      keys: create()
    });
  }
);

// ===============================
// ADMIN VERIFIKASI PEMBAYARAN
// ===============================

app.post("/api/admin/approve/:id",
  adminOnly,
  (req, res) => {

    const tx = db.prepare(
      "SELECT * FROM transactions WHERE id=?"
    ).get(req.params.id);

    if (!tx) {
      return res.status(404).json({
        error: "TRANSAKSI TIDAK DITEMUKAN"
      });
    }

    if (tx.status === "PAID" && tx.issued) {
      return res.json({
        success: true,
        message: "KEY SUDAH DITERBITKAN"
      });
    }

    if (tx.status !== "PENDING") {
      return res.status(400).json({
        error: "STATUS TRANSAKSI TIDAK DAPAT DISETUJUI"
      });
    }

    const selected = plans[tx.plan];

    const issue = db.transaction(() => {
      const keys = [];

      for (let i = 0; i < tx.quantity; i++) {
        const code = makeKey();

        db.prepare(`
          INSERT INTO keys_table
          (key_code, plan, duration_days, created_at)
          VALUES (?, ?, ?, ?)
        `).run(
          code,
          tx.plan,
          selected.days,
          now()
        );

        keys.push(code);
      }

      db.prepare(`
        UPDATE transactions
        SET status='PAID', issued=1
        WHERE id=? AND status='PENDING'
      `).run(tx.id);

      return keys;
    });

    try {
      const keys = issue();

      res.json({
        success: true,
        message: "PEMBAYARAN DISETUJUI DAN KEY DITERBITKAN",
        keys
      });
    } catch (error) {
      res.status(500).json({
        error: "GAGAL MENERBITKAN KEY"
      });
    }
  }
);

// ===============================
// LOGIN KEY
// ===============================

app.post("/api/login", (req, res) => {
  const code = String(req.body.key || "")
    .trim().toUpperCase();

  const key = db.prepare(`
    SELECT * FROM keys_table WHERE key_code=?
  `).get(code);

  if (!key || key.status === "REVOKED" ||
      key.status === "EXPIRED") {
    return res.status(401).json({
      error: "KEY TIDAK VALID"
    });
  }

  if (key.status === "UNUSED") {
    const activated = now();

    const expires = key.duration_days
      ? activated + key.duration_days * 86400000
      : null;

    db.prepare(`
      UPDATE keys_table
      SET status='ACTIVE',
          activated_at=?,
          expires_at=?
      WHERE id=?
    `).run(activated, expires, key.id);
  }

  const updated = db.prepare(
    "SELECT * FROM keys_table WHERE id=?"
  ).get(key.id);

  if (updated.expires_at &&
      updated.expires_at <= now()) {
    db.prepare(
      "UPDATE keys_table SET status='EXPIRED' WHERE id=?"
    ).run(key.id);

    return res.status(403).json({
      error: "KEY SUDAH KEDALUWARSA"
    });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).end();

    req.session.keyId = updated.id;
    req.session.role = "USER";

    res.json({
      success: true,
      plan: updated.plan,
      expires_at: updated.expires_at,
      permanent: updated.expires_at === null
    });
  });
});

app.get("/api/me", userOnly, (req, res) => {
  res.json({
    key: req.key.key_code,
    plan: req.key.plan,
    status: req.key.status,
    expires_at: req.key.expires_at,
    permanent: req.key.expires_at === null
  });
});

// ===============================
// HOST
// ===============================

app.post("/api/hosts", userOnly, (req, res) => {
  const username = String(
    req.body.username || ""
  ).trim().replace(/^@/, "");

  if (!/^[a-zA-Z0-9._]{2,24}$/.test(username)) {
    return res.status(400).json({
      error: "USERNAME TIKTOK TIDAK VALID"
    });
  }

  const id = crypto.randomUUID();

  db.prepare(`
    INSERT INTO hosts
    (id, owner_key, tiktok_username, created_at)
    VALUES (?, ?, ?, ?)
  `).run(
    id,
    req.key.key_code,
    username,
    now()
  );

  db.prepare(`
    INSERT INTO game_settings (host_id)
    VALUES (?)
  `).run(id);

  res.json({
    success: true,
    host: {
      id,
      username,
      connection: "DISCONNECTED"
    }
  });
});

app.get("/api/hosts", userOnly, (req, res) => {
  const hosts = db.prepare(`
    SELECT id, tiktok_username, connection_status
    FROM hosts WHERE owner_key=?
  `).all(req.key.key_code);

  res.json(hosts);
});

// Tidak mengklaim TikTok LIVE aktif tanpa konektor asli.
app.post("/api/hosts/:hostId/connect",
  userOnly,
  hostAccess,
  (req, res) => {

    if (process.env.TIKTOK_CONNECTOR_ENABLED !== "true") {
      return res.status(503).json({
        connected: false,
        error: "KONEKTOR TIKTOK LIVE BELUM DIKONFIGURASI"
      });
    }

    res.status(503).json({
      connected: false,
      error: "ADAPTER TIKTOK LIVE BELUM DIPASANG"
    });
  }
);

app.post("/api/hosts/:hostId/disconnect",
  userOnly,
  hostAccess,
  (req, res) => {

    db.prepare(`
      UPDATE hosts
      SET connection_status='DISCONNECTED'
      WHERE id=?
    `).run(req.host.id);

    res.json({
      success: true,
      connection: "DISCONNECTED"
    });
  }
);

// ===============================
// PENGATURAN ELIMINASI
// ===============================

app.put("/api/hosts/:hostId/settings",
  userOnly,
  hostAccess,
  (req, res) => {

    const { lock_mode, duration } = req.body;

    if (!["LOCKED", "NO_LOCKED"].includes(lock_mode)) {
      return res.status(400).json({
        error: "MODE TIDAK VALID"
      });
    }

    const seconds = Number(duration);

    if (!Number.isInteger(seconds) ||
        seconds < 1 || seconds > 86400) {
      return res.status(400).json({
        error: "DURASI TIDAK VALID"
      });
    }

    db.prepare(`
      UPDATE game_settings
      SET lock_mode=?, elimination_duration=?
      WHERE host_id=?
    `).run(lock_mode, seconds, req.host.id);

    res.json({
      success: true,
      lock_mode,
      duration: seconds
    });
  }
);

// ===============================
// PESERTA ELIMINASI
// ===============================

app.get("/api/hosts/:hostId/participants",
  userOnly,
  hostAccess,
  (req, res) => {

    const participants = db.prepare(`
      SELECT * FROM participants
      WHERE host_id=? AND active=1
      ORDER BY id
    `).all(req.host.id);

    res.json(participants);
  }
);

app.post("/api/hosts/:hostId/participants",
  userOnly,
  hostAccess,
  (req, res) => {

    const name = String(req.body.name || "").trim();

    if (!name || name.length > 40) {
      return res.status(400).json({
        error: "NAMA PESERTA TIDAK VALID"
      });
    }

    const settings = db.prepare(`
      SELECT * FROM game_settings WHERE host_id=?
    `).get(req.host.id);

    if (settings.lock_mode === "LOCKED" &&
        req.body.timerExpired === true) {
      return res.status(403).json({
        error: "WAKTU HABIS. PESERTA TIDAK DAPAT JOIN."
      });
    }

    const result = db.prepare(`
      INSERT INTO participants
      (host_id, name, created_at)
      VALUES (?, ?, ?)
    `).run(req.host.id, name, now());

    res.json({
      success: true,
      participant_id: result.lastInsertRowid,
      name
    });
  }
);

app.delete("/api/hosts/:hostId/participants/:id",
  userOnly,
  hostAccess,
  (req, res) => {

    const result = db.prepare(`
      DELETE FROM participants
      WHERE id=? AND host_id=?
    `).run(
      req.params.id,
      req.host.id
    );

    res.json({
      success: result.changes > 0
    });
  }
);

app.delete("/api/hosts/:hostId/participants",
  userOnly,
  hostAccess,
  (req, res) => {

    db.prepare(`
      DELETE FROM participants WHERE host_id=?
    `).run(req.host.id);

    res.json({
      success: true,
      message: "PESERTA DIRESET"
    });
  }
);

// ===============================
// LELANG
// ===============================

app.post("/api/hosts/:hostId/auction",
  userOnly,
  hostAccess,
  (req, res) => {

    const duration = Number(req.body.duration);

    if (!Number.isInteger(duration) ||
        duration < 1 || duration > 86400) {
      return res.status(400).json({
        error: "DURASI LELANG TIDAK VALID"
      });
    }

    const endsAt = now() + duration * 1000;

    const result = db.prepare(`
      INSERT INTO auctions
      (host_id, status, duration, ends_at, created_at)
      VALUES (?, 'RUNNING', ?, ?, ?)
    `).run(
      req.host.id,
      duration,
      endsAt,
      now()
    );

    res.json({
      success: true,
      auction_id: result.lastInsertRowid,
      status: "RUNNING",
      ends_at: endsAt
    });
  }
);

app.get("/api/hosts/:hostId/auction",
  userOnly,
  hostAccess,
  (req, res) => {

    const auction = db.prepare(`
      SELECT * FROM auctions
      WHERE host_id=?
      ORDER BY id DESC LIMIT 1
    `).get(req.host.id);

    if (!auction) {
      return res.json({
        status: "NOT_STARTED"
      });
    }

    if (auction.status === "RUNNING" &&
        auction.ends_at <= now()) {

      db.prepare(`
        UPDATE auctions
        SET status='FINISHED'
        WHERE id=?
      `).run(auction.id);

      auction.status = "FINISHED";
    }

    res.json(auction);
  }
);

// ===============================
// LOGOUT
// ===============================

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});

// ===============================
// SERVER
// ===============================

const PORT = process.env.PORT || 3000;

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET BELUM DIATUR");
}

app.listen(PORT, () => {
  console.log("================================");
  console.log(" ZANN ELIMINASI VIP");
  console.log(" SERVER BERJALAN");
  console.log(" PORT:", PORT);
  console.log("================================");
});
