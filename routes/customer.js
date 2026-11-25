import { randomBytes } from 'node:crypto';
import { Problem, cleanText, equal, orderFields, paymentProof, stages } from '../security.js';
import { audit, findActiveMenuItem, nowSeconds, orderSelect, searchSql, transaction } from '../store.js';
import { readId, requireCustomer, show } from '../web.js';

function simulatePayment(paymentKey, requestId, owner, cents) {
    const receipt = 'SIM-' + randomBytes(8).toString('hex').toUpperCase();
    return { receipt, proof: paymentProof(paymentKey, requestId, owner, cents, receipt) };
}

export function addCustomerRoutes(app, db, paymentKey, checkRequestLimit) {
    function findCustomerOrder(orderId, customerId) {
        const row = db.prepare(orderSelect + ' WHERE orders.id = ? AND orders.owner = ?').get(orderId, customerId);
        if (!row) throw new Problem('Order could not be found.', 404);
        return row;
    }

    function placeOrder(owner, itemId, requestId, form) {
        const { quantity, address, notes } = orderFields(form);
        if (form.payment !== 'approve' && form.payment !== 'decline') {
            throw new Problem('Select a supported payment simulation.');
        }

        return transaction(db, () => {
            // A retry returns the saved order, even if staff removed the menu item later.
            const existingOrder = db.prepare('SELECT id, owner, item FROM orders WHERE request_id = ?').get(requestId);
            if (existingOrder) {
                if (existingOrder.owner !== owner || existingOrder.item !== itemId) {
                    throw new Problem('Open checkout again before placing your order.', 409);
                }
                return existingOrder.id;
            }

            const item = findActiveMenuItem(db, itemId);
            if (form.payment === 'decline') {
                throw new Problem('Payment was declined by the simulator. No order was placed.', 422);
            }
            const cents = item.cents * quantity;
            const { receipt, proof } = simulatePayment(paymentKey, requestId, owner, cents);
            const expectedProof = paymentProof(paymentKey, requestId, owner, cents, receipt);
            if (!equal(proof, expectedProof)) {
                throw new Problem('The payment response could not be verified. No order was placed.', 502);
            }

            const saved = db.prepare(`INSERT INTO orders
                (request_id, owner, item, item_name, quantity, address, notes, cents, receipt, created)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
                .run(requestId, owner, itemId, item.name, quantity, address, notes, cents, receipt, nowSeconds());
            const orderId = Number(saved.lastInsertRowid);
            audit(db, owner, 'Checkout confirmed', orderId, `Sandbox receipt ${receipt}`);
            return orderId;
        });
    }

    app.get('/', (req, res) => {
        const query = cleanText(req.query.q ?? '', 'Search', 0, 80);
        const rows = db.prepare(searchSql).all(query, query);
        show(res, 'menu', 'Menu', { rows, query });
    });

    app.get('/checkout/:id', (req, res, next) => {
        if (!req.signedInUser) return res.redirect(303, '/login');
        next();
    }, requireCustomer, (req, res) => {
        const row = findActiveMenuItem(db, readId(req.params.id));
        show(res, 'checkout', 'Checkout', { row, requestId: randomBytes(16).toString('hex'), values: {} });
    });

    app.post('/checkout/:id', requireCustomer, (req, res) => {
        const owner = req.signedInUser.id;
        checkRequestLimit(`checkout:${owner}`, 5, 60);
        const itemId = readId(req.params.id);
        const requestId = req.body.request_id ?? '';
        if (!/^[0-9a-f]{32}$/.test(requestId)) throw new Problem('Open checkout again before placing your order.');
        try {
            const orderId = placeOrder(owner, itemId, requestId, req.body);
            res.redirect(303, `/orders/${orderId}`);
        } catch (error) {
            if (!(error instanceof Problem)) throw error;
            const row = findActiveMenuItem(db, itemId);
            show(res, 'checkout', 'Checkout', { row, requestId, values: req.body, message: error.message }, error.status);
        }
    });

    app.get('/orders', requireCustomer, (req, res) => {
        const rows = db.prepare(orderSelect + ' WHERE orders.owner = ? ORDER BY orders.id DESC').all(req.signedInUser.id);
        show(res, 'orders', 'My orders', { rows });
    });

    app.get('/orders/:id/status', requireCustomer, (req, res) => {
        const row = findCustomerOrder(readId(req.params.id), req.signedInUser.id);
        res.json({ stage: row.status, label: stages[row.status] });
    });

    app.get('/orders/:id', requireCustomer, (req, res) => {
        const row = findCustomerOrder(readId(req.params.id), req.signedInUser.id);
        show(res, 'order', 'Track order', { row });
    });
}
