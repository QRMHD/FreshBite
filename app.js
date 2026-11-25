import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import express from 'express';
import ejs from 'ejs';
import { Problem, equal, maxOrderQuantity, minDistinctPasswordChars, minPasswordLength, stages, tokenDigest } from './security.js';
import { nowSeconds } from './store.js';
import { show } from './web.js';
import { addAccountRoutes } from './routes/account.js';
import { addCustomerRoutes } from './routes/customer.js';
import { addStaffRoutes } from './routes/staff.js';

function rm(cents) {
    return `RM ${(cents / 100).toFixed(2)}`;
}

function numberLabel(id) {
    return `#${String(id).padStart(4, '0')}`;
}

function stamp(seconds) {
    const isoDate = new Date(seconds * 1000).toISOString();
    return isoDate.slice(0, 16).replace('T', ' ') + ' UTC';
}

function prepareResponse(req, res, next) {
    res.set({
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    });
    res.locals.csrf = '';
    res.locals.user = null;
    const port = req.socket.localPort;
    const localHosts = [`127.0.0.1:${port}`, `localhost:${port}`];
    const validHost = process.env.VERCEL
        ? typeof req.headers.host === 'string' && req.headers.host.length > 0 && !/\s/.test(req.headers.host)
        : localHosts.includes(req.headers.host);
    if (!validHost || req.originalUrl.length > 600) {
        throw new Problem('Open the app using its local address.', 400);
    }
    next();
}

function requireFormContentType(req, res, next) {
    if (!req.is('application/x-www-form-urlencoded')) {
        throw new Problem('Unsupported form format.', 415);
    }
    next();
}

function checkForm(req, res, next) {
    const fields = Object.values(req.body ?? {});
    for (const field of fields) {
        if (typeof field !== 'string') {
            throw new Problem('Duplicate fields are not allowed.');
        }
    }
    const formToken = req.body?.csrf ?? '';
    if (!req.session || !equal(req.session.csrf, formToken)) {
        throw new Problem('The form expired or could not be verified. Open it again.', 403);
    }
    next();
}

function showError(error, req, res, next) {
    if (res.headersSent) return next(error);

    if (error instanceof Problem || [400, 413, 415].includes(error.status)) {
        let message = 'Invalid or unsupported form data.';
        if (error instanceof Problem) {
            message = error.message;
        } else if (error.status === 413) {
            message = 'The request is too large.';
        }
        return show(res, 'error', 'Request error', {
            heading: 'Request could not be completed',
            detail: 'Check your details and try again.',
            message,
        }, error.status);
    }

    const reference = randomBytes(4).toString('hex');
    console.error(`Request failure ref=${reference} type=${error.name}`);
    const databaseBusy = error.errcode === 5 || error.errcode === 6;
    return show(res, 'error', 'Temporary problem', {
        heading: 'Temporarily unavailable',
        detail: `Try again in a moment. Reference ${reference}.`,
    }, databaseBusy ? 503 : 500);
}

export function createApp(db, paymentKey, seedKey, { secure = false } = {}) {
    const app = express();
    app.disable('x-powered-by');
    app.set('query parser', 'simple');
    app.set('views', fileURLToPath(new URL('./views', import.meta.url)));
    app.engine('html', ejs.renderFile);
    app.set('view engine', 'html');
    Object.assign(app.locals, { rm, stages, numberLabel, stamp, maxOrderQuantity, minPasswordLength, minDistinctPasswordChars });

    const limits = new Map();

    function checkRequestLimit(bucket, maximum, seconds) {
        const now = nowSeconds();
        for (const [name, limit] of limits) {
            if (limit.end <= now) limits.delete(name);
        }
        const limit = limits.get(bucket) ?? { end: now + seconds, hits: 0 };
        if (limit.hits >= maximum) {
            throw new Problem('Too many requests. Try again shortly.', 429);
        }
        limit.hits += 1;
        limits.set(bucket, limit);
    }

    function loadSession(req, res, next) {
        const cookie = req.headers.cookie ?? '';
        const match = /(?:^|;\s*)freshbite=([A-Za-z0-9_-]{43})(?=;|$)/.exec(cookie);
        req.session = null;
        req.sessionUser = null;
        req.signedInUser = null;

        if (match) {
            // The cookie carries the original token. SQLite stores only its hash.
            const digest = tokenDigest(match[1]);
            const session = db.prepare('SELECT * FROM sessions WHERE digest = ? AND expires > ?')
                .get(digest, nowSeconds());
            if (session) {
                req.session = session;
                res.locals.csrf = session.csrf;
                if (session.user_id !== null) {
                    req.sessionUser = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
                }
                // Only the ready stage has completed the authenticator check.
                if (session.stage === 'ready') {
                    req.signedInUser = req.sessionUser;
                }
            }
        }
        res.locals.user = req.signedInUser;
        next();
    }

    app.use(prepareResponse);
    app.use(express.static(fileURLToPath(new URL('./public', import.meta.url)), { cacheControl: false, index: false }));

    // Read the form first, then load the current session and check the form token.
    const parseForm = express.urlencoded({ extended: false, limit: '4kb', parameterLimit: 12, inflate: false });
    app.post(/.*/, requireFormContentType, parseForm);
    app.use(loadSession);
    app.post(/.*/, checkForm);

    addAccountRoutes(app, db, seedKey, secure, checkRequestLimit);
    addCustomerRoutes(app, db, paymentKey, checkRequestLimit);
    addStaffRoutes(app, db);

    app.use((req, res, next) => next(new Problem('Page could not be found.', 404)));
    app.use(showError);
    return app;
    
    app.listen('3000','127.0.0.1',() =>{
        console.log("This server is working on port 3000")
    })
}
