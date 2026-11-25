import { readFileSync } from 'node:fs';
import { createServer as createHttp } from 'node:http';
import { createServer as createHttps } from 'node:https';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { createApp } from './app.js';
import { dataFolder, openDatabase, readPaymentKey } from './store.js';

const { values } = parseArgs({ options: { https: { type: 'boolean' }, port: { type: 'string' } } });
const port = Number(values.port ?? process.env.PORT ?? 8443);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
    console.error('Use a valid port from 0 to 65535.');
    process.exit(1);
}

let tls;
if (values.https) {
    try {
        tls = { cert: readFileSync(join(dataFolder, 'localhost.pem')),
            key: readFileSync(join(dataFolder, 'localhost-key.pem')), minVersion: 'TLSv1.2' };
    } catch {
        console.error('HTTPS requires data/localhost.pem and data/localhost-key.pem. See README.md.');
        process.exit(1);
    }
}

let storage;
try {
    storage = openDatabase();
} catch (error) {
    console.error(error.message);
    process.exit(1);
}
const app = createApp(storage.db, readPaymentKey(), storage.seedKey, { secure: Boolean(tls) });
const server = tls ? createHttps(tls, app) : createHttp(app);
server.listen(port, '127.0.0.1', () => {
    console.log(`FreshBite running at ${tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}`);
});
