import { rmSync, writeFileSync } from 'node:fs';
import { openDatabase } from '../store.js';

const destination = process.argv[2];
if (!destination) {
    console.error('Usage: npm run backup -- <new-filename>');
    process.exit(1);
}
let db;
let created = false;
try {
    writeFileSync(destination, '', { flag: 'wx', mode: 0o600 });
    created = true;
    ({ db } = openDatabase());
    db.prepare('VACUUM INTO ?').run(destination);
    console.log(`Database snapshot saved to ${destination}`);
} catch (error) {
    if (created) rmSync(destination, { force: true });
    console.error(error.code === 'EEXIST' ? 'Choose a new backup path.' : error.message);
    process.exitCode = 1;
} finally {
    db?.close();
}
