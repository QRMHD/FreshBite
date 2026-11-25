import { Problem, cleanText, stages } from '../security.js';
import { audit, findActiveMenuItem, orderSelect, transaction } from '../store.js';
import { readId, requireStaff, show } from '../web.js';

const orderStatuses = stages.map((_, index) => String(index));
const advanceableStatuses = orderStatuses.slice(0, -1);

export function addStaffRoutes(app, db) {
    // Staff can choose a status or view every paid order.
    app.get('/admin', requireStaff, (req, res) => {
        const status = orderStatuses.includes(req.query.status) ? req.query.status : '';
        let rows;
        if (status === '') {
            rows = db.prepare(orderSelect + ' ORDER BY orders.id DESC').all();
        } else {
            rows = db.prepare(orderSelect + ' WHERE orders.status = ? ORDER BY orders.id DESC').all(Number(status));
        }
        show(res, 'admin', 'Order operations', { rows, status });
    });

    app.get('/admin/menu', requireStaff, (req, res) => {
        const rows = db.prepare('SELECT * FROM menu WHERE archived = 0 ORDER BY id').all();
        show(res, 'staff-menu', 'Manage menu', { rows });
    });

    app.get('/admin/menu/new', requireStaff, (req, res) => {
        show(res, 'menu-form', 'Add menu item', { itemId: null, values: {} });
    });

    app.get('/admin/menu/:id/edit', requireStaff, (req, res) => {
        const row = findActiveMenuItem(db, readId(req.params.id));
        show(res, 'menu-form', 'Edit menu item', {
            itemId: row.id, values: { ...row, price: (row.cents / 100).toFixed(2) },
        });
    });

    function saveMenuItem(req, res) {
        const itemId = req.params.id === undefined ? null : readId(req.params.id);
        const values = req.body;
        const title = itemId === null ? 'Add menu item' : 'Edit menu item';
        try {
            const name = cleanText(values.name, 'Item name', 1, 80);
            const restaurant = cleanText(values.restaurant, 'Restaurant', 1, 80);
            const description = cleanText(values.description, 'Description', 1, 240, { multiline: true });
            const category = cleanText(values.category, 'Category', 1, 40);
            const price = (values.price ?? '').trim();
            if (!/^[0-9]{1,4}(?:\.[0-9]{1,2})?$/.test(price) || Number(price) <= 0) {
                throw new Problem('Enter a price from RM 0.01 to RM 9999.99.');
            }
            const cents = Math.round(Number(price) * 100);

            transaction(db, () => {
                if (itemId === null) {
                    const result = db.prepare('INSERT INTO menu(name, restaurant, description, cents, category) VALUES (?, ?, ?, ?, ?)')
                        .run(name, restaurant, description, cents, category);
                    audit(db, req.signedInUser.id, 'Menu item added', null, `#${result.lastInsertRowid} · ${name}`);
                } else {
                    findActiveMenuItem(db, itemId);
                    db.prepare('UPDATE menu SET name = ?, restaurant = ?, description = ?, cents = ?, category = ? WHERE id = ?')
                        .run(name, restaurant, description, cents, category, itemId);
                    audit(db, req.signedInUser.id, 'Menu item edited', null, `#${itemId} · ${name}`);
                }
            });
            res.redirect(303, '/admin/menu');
        } catch (error) {
            if (!(error instanceof Problem)) throw error;
            show(res, 'menu-form', title, { itemId, values, message: error.message }, error.status);
        }
    }

    app.post('/admin/menu/new', requireStaff, saveMenuItem);
    app.post('/admin/menu/:id/edit', requireStaff, saveMenuItem);

    app.get('/admin/menu/:id/remove', requireStaff, (req, res) => {
        const row = findActiveMenuItem(db, readId(req.params.id));
        show(res, 'menu-remove', 'Remove menu item', { row });
    });

    app.post('/admin/menu/:id/remove', requireStaff, (req, res) => {
        const itemId = readId(req.params.id);
        transaction(db, () => {
            // Hide the item from the menu while retaining its link to past orders.
            const row = findActiveMenuItem(db, itemId);
            db.prepare('UPDATE menu SET archived = 1 WHERE id = ?').run(itemId);
            audit(db, req.signedInUser.id, 'Menu item removed', null, `#${itemId} · ${row.name}`);
        });
        res.redirect(303, '/admin/menu');
    });

    app.get('/admin/audit', requireStaff, (req, res) => {
        const rows = db.prepare(`SELECT audit.*, users.name FROM audit JOIN users
            ON audit.actor = users.id ORDER BY audit.id DESC LIMIT 100`).all();
        show(res, 'audit', 'Audit trail', { rows });
    });

    app.post('/admin/orders/:id', requireStaff, (req, res) => {
        const orderId = readId(req.params.id);
        if (!advanceableStatuses.includes(req.body.previous)) {
            throw new Problem('Invalid status transition.');
        }
        const stage = Number(req.body.previous);
        const nextStage = stage + 1;
        transaction(db, () => {
            // The previous status must still match when the update runs.
            const result = db.prepare('UPDATE orders SET status = ? WHERE id = ? AND status = ?')
                .run(nextStage, orderId, stage);
            if (!result.changes) throw new Problem('The order was already updated or could not be found. Reload the operations page.', 409);
            audit(db, req.signedInUser.id, 'Status changed by staff', orderId, `${stages[stage]} to ${stages[nextStage]}`);
        });
        const status = req.query.status;
        res.redirect(303, orderStatuses.includes(status) ? `/admin?status=${status}` : '/admin');
    });
}
