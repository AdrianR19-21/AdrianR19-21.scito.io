const crypto = require('crypto');

const password = process.argv[2];
if (!password) {
  console.error('Usage: node generate-password-hash.js "your-password"');
  process.exit(1);
}

const salt = crypto.randomBytes(16);
const hash = crypto.scryptSync(password, salt, 64);

console.log('SETUP_PASSWORD_SALT=' + salt.toString('hex'));
console.log('SETUP_PASSWORD_HASH=' + hash.toString('hex'));
console.log('');
console.log('Add both values to your .env and remove SETUP_PASSWORD for better security.');
