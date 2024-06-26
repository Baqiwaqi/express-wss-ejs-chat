import sqlite3 from "sqlite3";
import { sync } from "mkdirp";
import crypto from "crypto";

sync("./src/db");

var db = new sqlite3.Database("./src/db/sqlite.db");

db.serialize(() => {
  db.run(
    "CREATE TABLE IF NOT EXISTS users ( \
    id INTEGER PRIMARY KEY AUTOINCREMENT, \
    username TEXT UNIQUE, \
    hashed_password BLOB, \
    salt BLOB \
  )"
  );

  const salt = crypto.randomBytes(16);

  db.run(
    "INSERT OR IGNORE INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
    ["alice", crypto.pbkdf2Sync("letmein", salt, 310000, 32, "sha256"), salt]
  );
});

export default db;
