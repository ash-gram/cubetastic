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
PRAGMA user_version=1;
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
