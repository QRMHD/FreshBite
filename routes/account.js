import { randomBytes } from 'node:crypto';
import QRCode from 'qrcode';
import { Problem, authenticator, cleanText, equal, matchingStep, openSeed,
    passwordHash, passwordPolicy, username } from '../security.js';
import { addUser, nowSeconds, replaceSession, transaction } from '../store.js';
import { requireCustomer, requireSignedIn, show } from '../web.js';

// Run the same password check even when the username is unknown.
const dummySalt = Buffer.alloc(16);
const dummyHash = Buffer.alloc(32);

export function addAccountRoutes(app, db, seedKey, secure, checkRequestLimit) {
    function setSessionCookie(req, res, session) {
        req.session = session;
        res.locals.csrf = session.csrf;
        res.cookie('freshbite', session.raw, { httpOnly: true, sameSite: 'strict', secure, path: '/' });
    }

    function rotateSession(req, res, userId = null, stage = 'anonymous') {
        const session = transaction(db, () => replaceSession(db, req.session, userId, stage));
        setSessionCookie(req, res, session);
    }

    function recordFailedAttempt(user) {
        const now = nowSeconds();
        const previousLockExpired = user.locked_until > 0 && user.locked_until <= now;
        const failures = previousLockExpired ? 1 : user.failures + 1;
        const lockedUntil = failures >= 5 ? now + 60 : 0;
        db.prepare('UPDATE users SET failures = ?, locked_until = ? WHERE id = ?')
            .run(failures, lockedUntil, user.id);
    }

    async function showAuthenticatorForm(res, user, status = 200, message = null) {
        let qr = '';
        let setupKey = '';
        if (!user.enrolled) {
            setupKey = openSeed(user.secret, seedKey, user.name);
            qr = await QRCode.toString(authenticator(user.name, setupKey).toString(),
                { type: 'svg', width: 145, margin: 4 });
        }
        return show(res, 'mfa', 'Verify your sign-in', { setupKey, qr, message }, status);
    }

    app.get(['/login', '/register'], (req, res) => {
        if (req.signedInUser) return res.redirect(303, req.signedInUser.role === 'admin' ? '/admin' : '/');
        if (!req.session) rotateSession(req, res);
        const register = req.path === '/register';
        show(res, 'auth', register ? 'Create account' : 'Sign in', { register });
    });

    app.post('/register', (req, res) => {
        if (req.signedInUser) throw new Problem('Sign out before creating another account.', 409);
        checkRequestLimit(`register:${req.ip}`, 8, 60);
        try {
            const name = username(req.body.name ?? '');
            const display = cleanText(req.body.display ?? '', 'Display name', 2, 60);
            const password = passwordPolicy(req.body.password ?? '');
            const session = transaction(db, () => {
                const userId = addUser(db, seedKey, name, display, password, 'customer');
                return replaceSession(db, req.session, userId, 'challenge');
            });
            setSessionCookie(req, res, session);
            res.redirect(303, '/mfa');
        } catch (error) {
            if (!(error instanceof Problem)) throw error;
            show(res, 'auth', 'Create account', { register: true, message: error.message }, error.status);
        }
    });

    app.post('/login', (req, res) => {
        if (req.signedInUser) throw new Problem('Sign out before starting another session.', 409);
        checkRequestLimit(`login:${req.ip}`, 30, 60);
        const name = (req.body.name ?? '').trim().toLowerCase();
        const user = db.prepare('SELECT * FROM users WHERE name = ?').get(name);
        const password = req.body.password ?? '';
        const passwordToCheck = Buffer.byteLength(password) > 128 ? '' : password;
        const salt = user?.salt ?? dummySalt;
        const digest = passwordHash(passwordToCheck, salt);
        const passwordMatches = equal(digest, user?.password ?? dummyHash);
        const accountAvailable = user && user.locked_until <= nowSeconds();
        if (!passwordMatches || !accountAvailable) {
            if (accountAvailable) recordFailedAttempt(user);
            return show(res, 'auth', 'Sign in', { register: false,
                message: 'Sign-in failed. Check your details or wait before trying again.' }, 401);
        }
        // The password passed. The session still needs the authenticator code.
        rotateSession(req, res, user.id, 'challenge');
        res.redirect(303, '/mfa');
    });

    app.get('/mfa', (req, res) => {
        if (req.session?.stage !== 'challenge' || !req.sessionUser) return res.redirect(303, '/login');
        return showAuthenticatorForm(res, req.sessionUser);
    });

    app.post('/mfa', (req, res) => {
        if (req.session?.stage !== 'challenge' || !req.sessionUser) throw new Problem('Start sign-in again.', 401);
        const user = req.sessionUser;
        checkRequestLimit(`mfa:${user.id}`, 25, 60);
        if (user.locked_until > nowSeconds()) throw new Problem('Verification is temporarily locked. Try again later.', 429);
        const step = matchingStep(user, req.body.code ?? '', seedKey);
        if (step === null) {
            recordFailedAttempt(user);
            return showAuthenticatorForm(res, user, 401, 'The code was invalid or already used.');
        }
        const session = transaction(db, () => {
            const updated = db.prepare(`UPDATE users SET enrolled = 1, last_step = ?,
                failures = 0, locked_until = 0 WHERE id = ? AND last_step < ?`).run(step, user.id, step);
            if (!updated.changes) throw new Problem('The code was already used.', 401);
            return replaceSession(db, req.session, user.id, 'ready');
        });
        setSessionCookie(req, res, session);
        res.redirect(303, user.role === 'admin' ? '/admin' : '/');
    });

    app.post('/logout', requireSignedIn, (req, res) => {
        rotateSession(req, res);
        res.redirect(303, '/');
    });

    app.get('/account', requireCustomer, (req, res) => {
        show(res, 'account', 'My account', {
            saved: req.query.saved === '1',
            passwordChanged: req.query.password === 'changed',
        });
    });

    app.post('/account', requireCustomer, (req, res) => {
        const display = cleanText(req.body.display ?? '', 'Display name', 2, 60);
        db.prepare('UPDATE users SET display = ? WHERE id = ?').run(display, req.signedInUser.id);
        res.redirect(303, '/account?saved=1');
    });

    app.post('/account/password', requireCustomer, (req, res) => {
        const user = req.signedInUser;
        checkRequestLimit(`password:${user.id}`, 5, 60);
        try {
            const currentPassword = req.body.currentPassword ?? '';
            if (Buffer.byteLength(currentPassword) > 128 ||
                !equal(passwordHash(currentPassword, user.salt), user.password)) {
                throw new Problem('The current password is incorrect.');
            }
            const newPassword = passwordPolicy(req.body.newPassword ?? '');
            if (newPassword !== req.body.confirmPassword) {
                throw new Problem('The new passwords must match.');
            }
            if (newPassword === currentPassword) {
                throw new Problem('Choose a password different from your current one.');
            }
            const salt = randomBytes(16);
            const hash = passwordHash(newPassword, salt);
            const session = transaction(db, () => {
                const updated = db.prepare('UPDATE users SET password = ?, salt = ? WHERE id = ? AND password = ?')
                    .run(hash, salt, user.id, user.password);
                if (!updated.changes) throw new Problem('Your password changed. Sign in again.', 409);
                db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
                return replaceSession(db, null, user.id, 'ready');
            });
            setSessionCookie(req, res, session);
            res.redirect(303, '/account?password=changed');
        } catch (error) {
            if (!(error instanceof Problem)) throw error;
            show(res, 'account', 'My account', { saved: false, passwordChanged: false, message: error.message }, error.status);
        }
    });
}
