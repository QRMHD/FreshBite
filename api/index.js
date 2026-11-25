import { createApp } from '../app.js';
import { openDatabase, readPaymentKey } from '../store.js';

let appInstance;

function getApp() {
    if (!appInstance) {
        const storage = openDatabase();
        appInstance = createApp(storage.db, readPaymentKey(), storage.seedKey, {
            secure: Boolean(process.env.VERCEL),
        });
    }
    return appInstance;
}

export default function handler(req, res) {
    return getApp()(req, res);
}
