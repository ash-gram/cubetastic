"""Standalone storage, isolated from application releases."""
import sqlite3
from contextlib import closing
from pathlib import Path
from flask import current_app, g

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
 recovery_hash TEXT NOT NULL, settings TEXT, profile TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS solves (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 session INTEGER NOT NULL, category TEXT NOT NULL, time INTEGER NOT NULL,
 scramble TEXT NOT NULL, penalty INTEGER NOT NULL, solved_at INTEGER NOT NULL, comment TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS solves_owner_session ON solves(user_id, session, id);
CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY, user_id TEXT, title TEXT, message TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS rate_limits (bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_identities (
 provider TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 email TEXT NOT NULL, PRIMARY KEY(provider,subject), UNIQUE(provider,user_id)
);
CREATE INDEX IF NOT EXISTS solves_owner_id ON solves(user_id, id);
CREATE TABLE IF NOT EXISTS state_versions (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, revision INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO state_versions(user_id) SELECT id FROM users;
CREATE TRIGGER IF NOT EXISTS user_state_insert AFTER INSERT ON users BEGIN
 INSERT INTO state_versions(user_id) VALUES (NEW.id);
END;
CREATE TRIGGER IF NOT EXISTS user_state_update AFTER UPDATE ON users BEGIN
 UPDATE state_versions SET revision=revision+1 WHERE user_id=NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS solve_state_insert AFTER INSERT ON solves BEGIN
 UPDATE state_versions SET revision=revision+1 WHERE user_id=NEW.user_id;
END;
CREATE TRIGGER IF NOT EXISTS solve_state_update AFTER UPDATE ON solves BEGIN
 UPDATE state_versions SET revision=revision+1 WHERE user_id=NEW.user_id;
END;
CREATE TRIGGER IF NOT EXISTS solve_state_delete AFTER DELETE ON solves BEGIN
 UPDATE state_versions SET revision=revision+1 WHERE user_id=OLD.user_id;
END;
CREATE TRIGGER IF NOT EXISTS identity_state_insert AFTER INSERT ON oauth_identities BEGIN
 UPDATE state_versions SET revision=revision+1 WHERE user_id=NEW.user_id;
END;
CREATE TRIGGER IF NOT EXISTS identity_state_delete AFTER DELETE ON oauth_identities BEGIN
 UPDATE state_versions SET revision=revision+1 WHERE user_id=OLD.user_id;
END;
PRAGMA user_version=3;
'''

def connect(path):
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=15000')
    return db

def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(path)) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)

def get_db():
    if 'database' not in g:
        g.database = connect(current_app.config['DATABASE'])
    return g.database

def close_db(_error=None):
    db = g.pop('database', None)
    if db is not None:
        db.close()
