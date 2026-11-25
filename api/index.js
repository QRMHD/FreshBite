import { createApp } from '../app.js';
import { openDatabase, readPaymentKey } from '../store.js';

const storage = openDatabase();
const app = createApp(storage.db, readPaymentKey(), storage.seedKey, {
    secure: Boolean(process.env.VERCEL),
});

export default app;
