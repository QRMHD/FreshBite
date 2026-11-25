import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createApp } from '../app.js';
import { addUser, openDatabase, readPaymentKey, replaceSession } from '../store.js';

async function startTestApp(t) {
    const folder = mkdtempSync(join(tmpdir(), 'freshbite-test-'));
    let db;
    let server;
    t.after(async () => {
        if (server?.listening) {
            const closed = once(server, 'close');
            server.close();
            await closed;
        }
        db?.close();
        rmSync(folder, { recursive: true, force: true });
    });

    const storage = openDatabase(folder);
    db = storage.db;
    server = createServer(createApp(db, readPaymentKey(folder), storage.seedKey));
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const baseUrl = `http://127.0.0.1:${server.address().port}`;

    // Create a signed-in session so each test can focus on ordering.
    function createUser(name, role = 'customer', stage = 'ready') {
        const id = addUser(db, storage.seedKey, name, name, 'TestPassword123', role);
        return replaceSession(db, null, id, stage);
    }

    async function send(session, path, fields) {
        const options = {
            headers: { Cookie: `freshbite=${session.raw}` },
            redirect: 'manual',
        };
        if (fields) {
            options.method = 'POST';
            options.body = new URLSearchParams({ ...fields, csrf: session.csrf });
        }
        const response = await fetch(baseUrl + path, options);
        return {
            status: response.status,
            location: response.headers.get('location'),
            cookie: response.headers.get('set-cookie'),
            html: await response.text(),
        };
    }

    async function checkoutForm(customer, quantity) {
        const page = await send(customer, '/checkout/1');
        assert.equal(page.status, 200);
        const requestId = page.html.match(/name="request_id" value="([^"]+)"/);
        assert.ok(requestId, 'Checkout form contains a request ID');
        return {
            request_id: requestId[1],
            quantity,
            address: '12 Sample Street',
            notes: '',
            payment: 'approve',
        };
    }

    return { db, createUser, send, checkoutForm };
}

test('checkout accepts 20 portions and stores the correct total', async t => {
    const { db, createUser, send, checkoutForm } = await startTestApp(t);
    const customer = createUser('buyer');
    const form = await checkoutForm(customer, '20');

    const response = await send(customer, '/checkout/1', form);
    assert.equal(response.status, 303);
    const order = db.prepare('SELECT id, quantity, cents FROM orders').get();
    const item = db.prepare('SELECT cents FROM menu WHERE id = 1').get();
    assert.equal(response.location, `/orders/${order.id}`);
    assert.equal(order.quantity, 20);
    assert.equal(order.cents, item.cents * 20);
});

test('changing a password checks the current password and ends older sessions', async t => {
    const { db, createUser, send } = await startTestApp(t);
    const customer = createUser('buyer');
    const secondSession = replaceSession(db, null, customer.user_id, 'ready');
    const original = db.prepare('SELECT salt, password FROM users WHERE id = ?').get(customer.user_id);
    const fields = {
        currentPassword: 'TestPassword123',
        newPassword: 'NewPassword456',
        confirmPassword: 'NewPassword456',
    };

    assert.equal((await send(customer, '/account/password', { ...fields, currentPassword: 'Wrong' })).status, 400);
    assert.equal((await send(customer, '/account/password', { ...fields, confirmPassword: 'Mismatch' })).status, 400);
    const beforeChange = db.prepare('SELECT salt, password FROM users WHERE id = ?').get(customer.user_id);
    assert.deepEqual(beforeChange, original);

    const changed = await send(customer, '/account/password', fields);
    assert.equal(changed.location, '/account?password=changed');
    assert.notDeepEqual(db.prepare('SELECT salt FROM users WHERE id = ?').get(customer.user_id).salt, original.salt);
    assert.equal((await send(customer, '/account')).status, 401);
    assert.equal((await send(secondSession, '/account')).status, 401);
    const newSession = { raw: changed.cookie.match(/^freshbite=([^;]+)/)[1] };
    assert.equal((await send(newSession, '/account')).status, 200);

    const guest = replaceSession(db, null);
    assert.equal((await send(guest, '/login', { name: 'buyer', password: fields.currentPassword })).status, 401);
    assert.equal((await send(guest, '/login', { name: 'buyer', password: fields.newPassword })).location, '/mfa');
});

test('the MFA submission limit is separate for each account', async t => {
    const { db, createUser, send } = await startTestApp(t);
    const first = createUser('first_buyer', 'customer', 'challenge');
    const second = createUser('second_buyer', 'customer', 'challenge');
    db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(2_000_000_000, first.user_id);

    for (let attempt = 1; attempt <= 25; attempt++) {
        const response = await send(first, '/mfa', { code: 'invalid' });
        assert.match(response.html, /Verification is temporarily locked/);
    }
    const limited = await send(first, '/mfa', { code: 'invalid' });
    assert.equal(limited.status, 429);
    assert.match(limited.html, /Too many requests/);
    assert.equal((await send(second, '/mfa', { code: 'invalid' })).status, 401);
});

test('checkout rejects 21 portions without storing an order', async t => {
    const { db, createUser, send, checkoutForm } = await startTestApp(t);
    const customer = createUser('buyer');
    const form = await checkoutForm(customer, '21');

    const response = await send(customer, '/checkout/1', form);
    assert.equal(response.status, 400);
    assert.match(response.html, /Order between 1 and 20 portions/);
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM orders').get().count, 0);
});

test('checkout blocks submission six per customer and resets after 60 seconds', async t => {
    const clock = t.mock.method(Date, 'now', () => 1_800_000_000_000);
    const { db, createUser, send, checkoutForm } = await startTestApp(t);
    const first = createUser('first_buyer');
    const second = createUser('second_buyer');

    for (let attempt = 1; attempt <= 5; attempt++) {
        const form = await checkoutForm(first, '1');
        assert.equal((await send(first, '/checkout/1', form)).status, 303);
    }
    const sixthForm = await checkoutForm(first, '1');
    assert.equal((await send(first, '/checkout/1', sixthForm)).status, 429);
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM orders').get().count, 5);

    const secondForm = await checkoutForm(second, '1');
    assert.equal((await send(second, '/checkout/1', secondForm)).status, 303);

    const nextMinute = Date.now() + 60_000;
    clock.mock.mockImplementation(() => nextMinute);
    assert.equal((await send(first, '/checkout/1', sixthForm)).status, 303);
});

test('submitting the same checkout form twice stores one order', async t => {
    const { db, createUser, send, checkoutForm } = await startTestApp(t);
    const customer = createUser('buyer');
    const form = await checkoutForm(customer, '1');

    const first = await send(customer, '/checkout/1', form);
    const retry = await send(customer, '/checkout/1', form);
    assert.equal(first.status, 303);
    assert.equal(retry.status, 303);
    assert.equal(retry.location, first.location);
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM orders').get().count, 1);
});

test('staff can advance each delivery stage until the order is delivered', async t => {
    const { db, createUser, send, checkoutForm } = await startTestApp(t);
    const customer = createUser('buyer');
    const staff = createUser('staff', 'admin');
    const form = await checkoutForm(customer, '1');
    assert.equal((await send(customer, '/checkout/1', form)).status, 303);
    const order = db.prepare('SELECT id FROM orders').get();
    const path = `/admin/orders/${order.id}`;

    for (const previous of ['0', '1', '2']) {
        const response = await send(staff, path, { previous });
        assert.equal(response.status, 303);
        assert.equal(db.prepare('SELECT status FROM orders').get().status, Number(previous) + 1);
    }
    const operations = await send(staff, '/admin');
    assert.match(operations.html, /Delivery completed/);
    assert.doesNotMatch(operations.html, /name="previous"/);
    assert.equal((await send(staff, path, { previous: '3' })).status, 400);
    assert.equal(db.prepare('SELECT status FROM orders').get().status, 3);
});
