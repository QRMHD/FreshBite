import promptPassword from '@inquirer/password';
import { addUser, openDatabase } from '../store.js';
import { passwordPolicy, username } from '../security.js';

let db;
try {
    const name = username(process.argv[2] ?? 'staffdemo');
    const password = passwordPolicy(await promptPassword({ message: 'Admin password', mask: '*' }));
    if (password !== await promptPassword({ message: 'Confirm admin password', mask: '*' })) {
        throw new Error('Passwords do not match.');
    }
    const storage = openDatabase();
    db = storage.db;
    addUser(db, storage.seedKey, name, 'Operations staff', password, 'admin');
    console.log(`Created staff account ${name}. Sign in to enroll its authenticator.`);
} catch (error) {
    console.error(error.message);
    process.exitCode = 1;
} finally {
    db?.close();
}
