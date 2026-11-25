import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { Problem, isTotpSeed, newTotpSecret, openSeed, passwordHash, sealSeed, tokenDigest } from './security.js';

export const dataFolder = process.env.FRESHBITE_DATA ||
    (process.env.VERCEL ? join(tmpdir(), 'freshbite-data') : fileURLToPath(new URL('./data', import.meta.url)));
export function nowSeconds() {
    return Math.floor(Date.now() / 1000);
}

export const orderSelect = `SELECT orders.*, users.name AS buyer
    FROM orders JOIN users ON orders.owner = users.id`;
export const searchSql = `SELECT * FROM menu
    WHERE archived = 0 AND (instr(lower(name), lower(?)) > 0 OR instr(lower(restaurant), lower(?)) > 0)
    ORDER BY id`;

export function findActiveMenuItem(db, itemId) {
    const item = db.prepare('SELECT * FROM menu WHERE id = ? AND archived = 0').get(itemId);
    if (!item) {
        throw new Problem('That menu item could not be found.', 404);
    }
    return item;
}

// Write the change and its audit record together.
export function transaction(db, work) {
    db.exec('BEGIN IMMEDIATE');
    try {
        const result = work();
        db.exec('COMMIT');
        return result;
    } catch (error) {
        db.exec('ROLLBACK');
        throw error;
    }
}

function upgradeOrderQuantity(db) {
    const oldLimit = 'quantity BETWEEN 1 AND 10';
    const orderSchema = db.prepare("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'orders'");
    if (!orderSchema.get().sql.includes(oldLimit)) return;

    // SQLite requires a table rebuild to change an existing CHECK constraint.
    const { foreign_keys: foreignKeys } = db.prepare('PRAGMA foreign_keys').get();
    db.exec('PRAGMA foreign_keys = OFF');
    try {
        transaction(db, () => {
            const { sql } = orderSchema.get();
            if (!sql.includes(oldLimit)) return;
            const orderObjects = db.prepare(`SELECT sql FROM sqlite_schema
                WHERE tbl_name = 'orders' AND type IN ('index', 'trigger') AND sql IS NOT NULL`).all();
            const newOrderSchema = sql.replace(/^CREATE TABLE orders\b/, 'CREATE TABLE orders_new')
                .replace(oldLimit, 'quantity BETWEEN 1 AND 20');

            db.exec(newOrderSchema);
            db.exec('INSERT INTO orders_new SELECT * FROM orders');
            db.exec('DROP TABLE orders');
            db.exec('ALTER TABLE orders_new RENAME TO orders');
            for (const object of orderObjects) db.exec(object.sql);

            if (db.prepare('PRAGMA foreign_key_check').get()) {
                throw new Error('Order quantity upgrade could not preserve database references.');
            }
        });
    } finally {
        if (foreignKeys) db.exec('PRAGMA foreign_keys = ON');
    }
}

export function initDatabase(db) {
    const schema = readFileSync(new URL('./schema.sql', import.meta.url), 'utf8');
    const menu = JSON.parse(readFileSync(new URL('./menu.json', import.meta.url), 'utf8'));
    transaction(db, () => {
        db.exec(schema);
        // Older databases need these columns before they can use the current schema.
        if (!db.prepare('PRAGMA table_info(menu)').all().some(column => column.name === 'archived')) {
            db.exec('ALTER TABLE menu ADD COLUMN archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0, 1))');
        }
        if (!db.prepare('PRAGMA table_info(orders)').all().some(column => column.name === 'item_name')) {
            db.exec('ALTER TABLE orders ADD COLUMN item_name TEXT');
            db.exec('UPDATE orders SET item_name = (SELECT name FROM menu WHERE menu.id = orders.item)');
        }
        const insert = db.prepare('INSERT OR IGNORE INTO menu(id,name,restaurant,description,cents,category) VALUES (?, ?, ?, ?, ?, ?)');
        for (const [index, row] of menu.entries()) {
            insert.run(index + 1, ...row);
        }
    });
    upgradeOrderQuantity(db);
    return db;
}

export function openDatabase(folder = dataFolder) {
    mkdirSync(folder, { recursive: true, mode: 0o700 });
    const path = join(folder, 'freshbite.sqlite3');
    try {
        writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
    } catch (error) {
        if (error.code !== 'EEXIST') throw error;
    }
    const db = new DatabaseSync(path, { timeout: 3000 });
    try {
        initDatabase(db);
        db.exec('PRAGMA secure_delete = ON');
        const seedKey = transaction(db, () => {
            const rows = db.prepare('SELECT id, name, secret FROM users').all();
            const key = readSeedKey(folder, rows.some(row => !isTotpSeed(row.secret)));
            const replace = db.prepare('UPDATE users SET secret = ? WHERE id = ?');
            for (const row of rows) {
                if (isTotpSeed(row.secret)) {
                    replace.run(sealSeed(row.secret, key, row.name), row.id);
                } else {
                    try {
                        openSeed(row.secret, key, row.name);
                    } catch {
                        throw new Error('Cannot open the stored MFA seeds. Restore the original TOTP_KEY or totp.key.');
                    }
                }
            }
            return key;
        });
        return { db, seedKey };
    } catch (error) {
        db.close();
        throw error;
    }
}

function readSeedKey(folder, hasSealedSeeds) {
    const configured = process.env.TOTP_KEY;
    if (configured !== undefined) {
        if (!/^[a-fA-F0-9]{64}$/.test(configured)) throw new Error('TOTP_KEY must contain 64 hexadecimal characters.');
        return Buffer.from(configured, 'hex');
    }
    const path = join(folder, 'totp.key');
    try {
        const key = readFileSync(path);
        if (key.length !== 32) throw new Error('Invalid local totp.key.');
        return key;
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        if (hasSealedSeeds) throw new Error('MFA key is missing. Restore the original TOTP_KEY or totp.key.');
    }
    const key = randomBytes(32);
    writeFileSync(path, key, { flag: 'wx', mode: 0o600 });
    return key;
}

export function readPaymentKey(folder = dataFolder) {
    const path = join(folder, 'payment.key');
    try {
        writeFileSync(path, randomBytes(32), { flag: 'wx', mode: 0o600 });
    } catch (error) {
        if (error.code !== 'EEXIST') throw error;
    }
    const key = readFileSync(path);
    if (key.length !== 32) throw new Error('Invalid sandbox payment key.');
    return key;
}

export function addUser(db, seedKey, name, display, password, role) {
    const salt = randomBytes(16);
    const hash = passwordHash(password, salt);
    const sealedSecret = sealSeed(newTotpSecret(), seedKey, name);
    const result = db.prepare(`INSERT INTO users(name, display, salt, password, secret, role)
        VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO NOTHING`)
        .run(name, display, salt, hash, sealedSecret, role);
    if (!result.changes) throw new Problem('That username is unavailable.');
    return Number(result.lastInsertRowid);
}

const sessionLifetimeSeconds = {
    anonymous: 3600,
    challenge: 300,
    ready: 7200,
};

export function replaceSession(db, oldSession, userId = null, stage = 'anonymous') {
    const now = nowSeconds();
    if (oldSession) {
        db.prepare('DELETE FROM sessions WHERE digest = ?').run(oldSession.digest);
    }
    db.prepare('DELETE FROM sessions WHERE expires <= ?').run(now);
    const raw = randomBytes(32).toString('base64url');
    const digest = tokenDigest(raw);
    const csrf = randomBytes(32).toString('base64url');
    const expires = now + sessionLifetimeSeconds[stage];
    db.prepare('INSERT INTO sessions (digest, user_id, stage, csrf, expires) VALUES (?, ?, ?, ?, ?)')
        .run(digest, userId, stage, csrf, expires);
    return { raw, digest, csrf, stage, user_id: userId };
}

export function audit(db, actor, event, orderId, detail) {
    db.prepare('INSERT INTO audit(actor,event,order_id,detail,created) VALUES (?, ?, ?, ?, ?)')
        .run(actor, event, orderId, detail, nowSeconds());
}
