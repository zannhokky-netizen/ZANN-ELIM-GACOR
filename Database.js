
const Database = require("better-sqlite3");

const db = new Database("zann-vip.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS keys_table (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_code TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL,
  duration_days INTEGER,
  status TEXT DEFAULT 'UNUSED',
  activated_at INTEGER,
  expires_at INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  quantity INTEGER NOT NULL,
  plan TEXT NOT NULL,
  amount INTEGER NOT NULL,
  payment_number TEXT NOT NULL,
  status TEXT DEFAULT 'PENDING',
  issued INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  owner_key TEXT NOT NULL,
  tiktok_username TEXT,
  connection_status TEXT DEFAULT 'DISCONNECTED',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS participants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id TEXT NOT NULL,
  name TEXT NOT NULL,
  box_number INTEGER,
  active INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS auctions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id TEXT NOT NULL,
  status TEXT DEFAULT 'NOT_STARTED',
  duration INTEGER DEFAULT 60,
  ends_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS game_settings (
  host_id TEXT PRIMARY KEY,
  lock_mode TEXT DEFAULT 'LOCKED',
  elimination_duration INTEGER DEFAULT 60,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS gift_events (
  event_id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL,
  sender TEXT NOT NULL,
  gift_name TEXT NOT NULL,
  quantity INTEGER DEFAULT 1,
  destination TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS admin_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`);

module.exports = db;
