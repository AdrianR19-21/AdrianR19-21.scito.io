#!/usr/bin/env node

/**
 * IT Setup - Generador de secretos cifrados
 *
 * Este script genera un blob cifrado AES-GCM con PBKDF2 para tus credenciales.
 * Uso: node encrypt-secrets.js
 *
 * Solo tienes que ejecutarlo una vez con tu contraseña y tus datos. Después:
 * 1. Copia el JSON de salida
 * 2. Reemplaza el contenido de <script id="encrypted-data"> en lista.html
 * 3. Sube el proyecto a GitHub: las credenciales quedarán cifradas
 */

const crypto = require('crypto');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function question(prompt) {
  return new Promise(resolve => {
    rl.question(prompt, resolve);
  });
}

async function deriveKey(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

async function encryptData(plaintext, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);

  const key = await deriveKey(password, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return {
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    ciphertext: Buffer.concat([ciphertext, authTag]).toString('base64'),
  };
}

async function main() {
  console.log('\n╔════════════════════════════════════════════╗');
  console.log('║   IT Setup - Generador de secretos cifrados ║');
  console.log('╚════════════════════════════════════════════╝\n');

  const password = await question('🔐 Contraseña para cifrar (debe ser la misma que usas en la web): ');

  console.log('\n📝 Ahora introduce los datos que deseas cifrar:\n');

  const dropboxEmail = await question('Dropbox Email: ');
  const dropboxPass = await question('Dropbox Password: ');
  const adminPass = await question('Admin Password (PC): ');

  const plainData = {
    dropbox_email: dropboxEmail,
    dropbox_pass: dropboxPass,
    admin_pass: adminPass,
  };

  console.log('\n⏳ Cifrando...');

  try {
    const encrypted = await encryptData(
      JSON.stringify(plainData),
      password
    );

    console.log('\n✅ ¡Éxito! Aquí está tu blob cifrado:\n');
    console.log('═'.repeat(50));
    console.log(JSON.stringify(encrypted, null, 2));
    console.log('═'.repeat(50));

    console.log('\n📋 Instrucciones:');
    console.log('1. Copia el JSON de arriba (completo, con {})');
    console.log('2. Abre lista.html en un editor de texto');
    console.log('3. Busca la línea: <script type="application/json" id="encrypted-data">');
    console.log('4. Reemplaza el contenido entre las etiquetas script con tu JSON');
    console.log('5. Guarda y listo: las credenciales quedarán cifradas y listas para GitHub');

    console.log('\n🔒 Recordatorios de Seguridad:');
    console.log('• Este script no guarda los datos: solo los procesa en memoria');
    console.log('• Solo distribuye el blob cifrado (JSON), nunca el texto plano');
    console.log('• Usa la misma contraseña en la web que la que usaste aquí');
    console.log('• PBKDF2 con 100k iteraciones ayuda frente a ataques de fuerza bruta');
    
    rl.close();
  } catch (err) {
    console.error('\n❌ Error al cifrar:', err.message);
    rl.close();
    process.exit(1);
  }
}

main();
