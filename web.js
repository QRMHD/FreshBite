import { Problem } from './security.js';

export function show(res, view, title, fields = {}, status = 200) {
    return res.status(status).render('layout', { view, title, message: null, ...fields });
}

export function readId(value) {
    if (!/^[1-9][0-9]{0,9}$/.test(value)) {
        throw new Problem('Page could not be found.', 404);
    }
    return Number(value);
}

function checkSignIn(req) {
    if (!req.signedInUser) {
        throw new Problem('Sign in and verify your authenticator to continue.', 401);
    }
}

export function requireSignedIn(req, res, next) {
    checkSignIn(req);
    next();
}

// Express calls the next route handler only after the role check passes.
function requireRole(role) {
    return function checkRole(req, res, next) {
        checkSignIn(req);
        if (req.signedInUser.role !== role) {
            throw new Problem('This page is restricted to authorized users.', 403);
        }
        next();
    };
}

export const requireCustomer = requireRole('customer');
export const requireStaff = requireRole('admin');
