'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'server-data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const PORT = parseInt(process.env.PORT, 10) || 8090;
const HOST = process.env.HOST || '0.0.0.0';
const ACCESS_TTL = 3600;
const MAX_BODY = 1024 * 1024;

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.htm': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.mjs': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.ico': 'image/x-icon',
    '.bmp': 'image/bmp',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf',
    '.otf': 'font/otf',
    '.eot': 'application/vnd.ms-fontobject',
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.mp3': 'audio/mpeg',
    '.txt': 'text/plain; charset=utf-8',
    '.xml': 'application/xml',
    '.pdf': 'application/pdf',
    '.map': 'application/json',
    '.wasm': 'application/wasm'
};

function ensureData() {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readJSON(file, fallback) {
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
        return fallback;
    }
}

function writeJSON(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString('hex');
}

function passwordsMatch(password, user) {
    const candidate = Buffer.from(hashPassword(password, user.salt), 'hex');
    const expected = Buffer.from(user.hash, 'hex');
    if (candidate.length !== expected.length) {
        return false;
    }
    return crypto.timingSafeEqual(candidate, expected);
}

function makeToken(prefix) {
    return (prefix || '') + crypto.randomBytes(24).toString('hex');
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        let size = 0;
        req.on('data', (chunk) => {
            size += chunk.length;
            if (size > MAX_BODY) {
                reject(new Error('payload_too_large'));
                req.destroy();
                return;
            }
            data += chunk;
        });
        req.on('end', () => resolve(data));
        req.on('error', reject);
    });
}

function parseBody(raw, contentType) {
    const ct = (contentType || '').toLowerCase();
    if (ct.indexOf('application/json') !== -1) {
        try {
            return JSON.parse(raw || '{}');
        } catch (e) {
            return {};
        }
    }
    const out = {};
    if (raw) {
        raw.split('&').forEach((pair) => {
            if (!pair) {
                return;
            }
            const i = pair.indexOf('=');
            const k = i === -1 ? pair : pair.slice(0, i);
            const v = i === -1 ? '' : pair.slice(i + 1);
            out[decodeURIComponent(k.replace(/\+/g, ' '))] = decodeURIComponent(v.replace(/\+/g, ' '));
        });
    }
    return out;
}

function sendJSON(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
        'Cache-Control': 'no-store'
    });
    res.end(body);
}

function handleFailure(res) {
    return (err) => {
        if (res.headersSent) {
            try {
                res.end();
            } catch (e) { /* ignore */ }
            return;
        }
        sendJSON(res, 500, { error: 'server_error', message: err && err.message });
    };
}

function createSession(username) {
    const sessions = readJSON(SESSIONS_FILE, {});
    const access = makeToken('msa.');
    const refresh = makeToken('rt.');
    const expiresAt = Date.now() + ACCESS_TTL * 1000;
    sessions[access] = { type: 'access', username, refresh, expiresAt };
    sessions[refresh] = { type: 'refresh', username, refresh, expiresAt };
    writeJSON(SESSIONS_FILE, sessions);
    return {
        access_token: access,
        refresh_token: refresh,
        expires_in: ACCESS_TTL,
        token_type: 'Bearer',
        skype_name: username
    };
}

function getSession(token) {
    if (!token) {
        return null;
    }
    return readJSON(SESSIONS_FILE, {})[token] || null;
}

async function handleLogin(req, res) {
    const body = parseBody(await readBody(req), req.headers['content-type']);
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    if (!username || !password) {
        return sendJSON(res, 400, { error: 'missing_credentials' });
    }

    const users = readJSON(USERS_FILE, {});
    const key = username.toLowerCase();
    let created = false;
    let user = users[key];

    if (!user) {
        const salt = crypto.randomBytes(16).toString('hex');
        user = {
            username: username,
            salt: salt,
            hash: hashPassword(password, salt),
            created: new Date().toISOString()
        };
        users[key] = user;
        writeJSON(USERS_FILE, users);
        created = true;
    } else if (!passwordsMatch(password, user)) {
        return sendJSON(res, 401, { error: 'invalid_password' });
    }

    const session = createSession(user.username);
    session.created = created;
    sendJSON(res, 200, session);
}

async function handleToken(req, res) {
    const body = parseBody(await readBody(req), req.headers['content-type']);
    const rec = getSession(body.refresh_token);

    if (!rec || rec.type !== 'refresh') {
        return sendJSON(res, 400, { error: 'invalid_grant' });
    }

    const sessions = readJSON(SESSIONS_FILE, {});
    Object.keys(sessions).forEach((token) => {
        if (sessions[token].refresh === body.refresh_token) {
            delete sessions[token];
        }
    });
    writeJSON(SESSIONS_FILE, sessions);

    sendJSON(res, 200, createSession(rec.username));
}

async function handleSkypetoken(req, res) {
    const body = parseBody(await readBody(req), req.headers['content-type']);
    const rec = getSession(body.access_token);

    if (!rec || rec.type !== 'access') {
        return sendJSON(res, 401, { error: 'invalid_token' });
    }

    sendJSON(res, 200, {
        skypetoken: makeToken('skypetoken.'),
        expires_in: ACCESS_TTL,
        skype_name: rec.username
    });
}

function serveFile(res, filePath) {
    fs.readFile(filePath, (err, data) => {
        if (err) {
            fs.readFile(path.join(ROOT, '404.html'), (e2, d2) => {
                if (e2) {
                    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
                    res.end('Not found');
                    return;
                }
                res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(d2);
            });
            return;
        }
        const ext = path.extname(filePath).toLowerCase();
        res.writeHead(200, {
            'Content-Type': MIME[ext] || 'application/octet-stream',
            'Content-Length': data.length
        });
        res.end(data);
    });
}

function serveStatic(res, pathname) {
    let rel;
    try {
        rel = decodeURIComponent(pathname);
    } catch (e) {
        res.writeHead(400);
        res.end('Bad request');
        return;
    }
    if (rel.endsWith('/')) {
        rel += 'index.html';
    }
    const resolved = path.resolve(path.join(ROOT, rel));
    if (resolved !== ROOT && !resolved.startsWith(ROOT + path.sep)) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
    }
    fs.stat(resolved, (err, stat) => {
        if (!err && stat.isDirectory()) {
            serveFile(res, path.join(resolved, 'index.html'));
            return;
        }
        serveFile(res, resolved);
    });
}

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,POST,PATCH,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Skype-Caller, Accept');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    let pathname;
    let params;
    try {
        const parsed = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
        pathname = parsed.pathname;
        params = parsed.searchParams;
    } catch (e) {
        res.writeHead(400);
        res.end('Bad request');
        return;
    }

    if (pathname === '/api/login' || pathname === '/api/register') {
        if (req.method !== 'POST') {
            res.writeHead(405);
            res.end('Method Not Allowed');
            return;
        }
        handleLogin(req, res).catch(handleFailure(res));
        return;
    }

    if (pathname === '/oauth20_token.srf') {
        if (req.method !== 'POST') {
            res.writeHead(405);
            res.end('Method Not Allowed');
            return;
        }
        handleToken(req, res).catch(handleFailure(res));
        return;
    }

    if (pathname === '/rps/v1/rps/skypetoken') {
        if (req.method !== 'POST') {
            res.writeHead(405);
            res.end('Method Not Allowed');
            return;
        }
        handleSkypetoken(req, res).catch(handleFailure(res));
        return;
    }

    if (pathname === '/oauth20_authorize.srf') {
        const username = params.get('username') || '';
        const target = (params.get('signup') ? '/register/' : '/login/') +
            (username ? ('?username=' + encodeURIComponent(username)) : '');
        res.writeHead(302, { Location: target });
        res.end();
        return;
    }

    if (pathname === '/oauth20_desktop.srf') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<!doctype html><meta charset="utf-8"><title>KSkype</title>');
        return;
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
        serveStatic(res, pathname);
        return;
    }

    res.writeHead(405);
    res.end('Method Not Allowed');
});

ensureData();
server.listen(PORT, HOST, () => {
    console.log('[KSkype server] listening on http://localhost:' + PORT);
    console.log('[KSkype server] serving ' + ROOT);
    console.log('[KSkype server] login endpoint: POST /api/login');
});
