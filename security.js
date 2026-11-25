import { createCipheriv, createDecipheriv, createHash, createHmac,
    pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';

export const stages = ['Confirmed', 'Preparing', 'Out for delivery', 'Delivered'];
export const maxNoteBytes = 64;
export const minPasswordLength = 8;
export const minDistinctPasswordChars = 6;
export const maxOrderQuantity = 20;

export class Problem extends Error {
    constructor(message, status = 400) {
        super(message);
        this.status = status;
    }
}

export function cleanText(value, label, min, max, { multiline = false } = {}) {
    if (typeof value !== 'string') throw new Problem(`Invalid ${label.toLowerCase()}.`);
    // Browsers submit textarea line breaks as CRLF. Store and count them as LF.
    let text = value.trim();
    let textToCheck = text;
    if (multiline) {
        text = text.replace(/\r\n?/g, '\n');
        textToCheck = text.replaceAll('\n', '');
    }
    if (/\p{C}/u.test(textToCheck)) throw new Problem(`${label} contains unsupported control characters.`);
    const length = Buffer.byteLength(text, 'utf8');
    if (length < min || length > max) {
        throw new Problem(`${label} must contain ${min}–${max} bytes after trimming.`);
    }
    return text;
}

export function username(value) {
    const name = value.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,24}$/.test(name)) {
        throw new Problem('Use 3–24 letters, digits or underscores for the username.');
    }
    return name;
}

export function passwordPolicy(password) {
    const characterCount = Array.from(password).length;
    const byteCount = Buffer.byteLength(password);
    const distinctCount = new Set(password).size;
    const containsControlCharacters = /[\u0000-\u001f]/u.test(password);
    if (characterCount < minPasswordLength || byteCount > 128 ||
        distinctCount < minDistinctPasswordChars || containsControlCharacters) {
        throw new Problem(`Use a password of at least ${minPasswordLength} characters, at most 128 bytes, with at least ${minDistinctPasswordChars} distinct characters.`);
    }
    return password;
}

export function passwordHash(password, salt) {
    return pbkdf2Sync(password, salt, 600_000, 32, 'sha256');
}

export function equal(left, right) {
    const leftBytes = Buffer.from(left);
    const rightBytes = Buffer.from(right);
    return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

export function newTotpSecret() {
    return new Secret({ size: 20 }).base32;
}

export const sealedSeedPrefix = 'gcm:v1:';
export const isTotpSeed = (seed) => typeof seed === 'string' && /^[A-Z2-7]{32}$/.test(seed);

// The stored record contains the random nonce, authentication tag, then encrypted secret.
export function sealSeed(seed, key, name) {
    if (!isTotpSeed(seed)) throw new Error('Invalid TOTP seed format.');
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    cipher.setAAD(Buffer.from(name, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(seed, 'utf8'), cipher.final()]);
    return sealedSeedPrefix + Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]).toString('base64url');
}

export function openSeed(sealed, key, name) {
    if (!sealed.startsWith(sealedSeedPrefix)) throw new Error('Invalid sealed TOTP seed.');
    const encoded = sealed.slice(sealedSeedPrefix.length);
    const raw = Buffer.from(encoded, 'base64url');
    if (raw.length !== 60 || raw.toString('base64url') !== encoded) {
        throw new Error('Invalid sealed TOTP seed.');
    }
    const nonce = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const ciphertext = raw.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    decipher.setAAD(Buffer.from(name, 'utf8'));
    decipher.setAuthTag(tag);
    const seed = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    if (!isTotpSeed(seed)) throw new Error('Invalid decrypted TOTP seed.');
    return seed;
}

export function authenticator(name, secret) {
    return new TOTP({ issuer: 'FreshBite', label: name, algorithm: 'SHA1',
        digits: 6, period: 30, secret: Secret.fromBase32(secret) });
}

export function matchingStep(user, code, seedKey) {
    if (!/^[0-9]{6}$/.test(code)) return null;
    const currentStep = Math.floor(Date.now() / 30_000);
    const totp = authenticator(user.name, openSeed(user.secret, seedKey, user.name));
    // Allow one time step of clock drift and reject steps already used.
    for (const step of [currentStep, currentStep - 1, currentStep + 1]) {
        if (step > user.last_step && equal(totp.generate({ timestamp: step * 30_000 }), code)) {
            return step;
        }
    }
    return null;
}

export function tokenDigest(raw) {
    return createHash('sha256').update(raw).digest('hex');
}

export function orderFields(form) {
    const raw = form.quantity ?? '';
    if (!/^[0-9]{1,3}$/.test(raw)) throw new Problem('Quantity must be a whole number.');
    const quantity = Number(raw);
    if (quantity < 1 || quantity > maxOrderQuantity) {
        throw new Problem(`Order between 1 and ${maxOrderQuantity} portions.`);
    }
    const address = cleanText(form.address ?? '', 'Address', 12, 180);
    if (!/[0-9]/.test(address) || (address.match(/\p{L}/gu)?.length ?? 0) < 4) {
        throw new Problem('Include a unit or street number and a street or building name.');
    }
    const notes = cleanText(form.notes ?? '', 'Notes', 0, maxNoteBytes, { multiline: true });
    return { quantity, address, notes };
}

export function paymentProof(key, requestId, owner, cents, receipt) {
    return createHmac('sha256', key).update(`${requestId}|${owner}|${cents}|${receipt}`).digest('hex');
}
