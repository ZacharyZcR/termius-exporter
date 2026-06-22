#!/usr/bin/env node
/**
 * Termius data exporter
 *
 * Extracts and decrypts all data from the local Termius database.
 * Output: termius_hosts.csv, ssh_keys/, snippets.csv
 *
 * Requires: npm install libsodium-wrappers keytar
 */

const sodium = require('libsodium-wrappers');
const keytar = require('keytar');
const fs = require('fs');
const path = require('path');
const os = require('os');

const BOM = '﻿';
const OUTPUT_DIR = __dirname;

function getDbPath() {
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library/Application Support/Termius/IndexedDB/file__0.indexeddb.leveldb');
  }
  if (process.platform === 'win32') {
    if (!process.env.APPDATA) throw new Error('APPDATA environment variable is not set');
    return path.join(process.env.APPDATA, 'Termius/IndexedDB/file__0.indexeddb.leveldb');
  }
  // Linux: XDG_CONFIG_HOME or ~/.config
  return path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'Termius/IndexedDB/file__0.indexeddb.leveldb');
}

// ==================== Decryption ====================

async function getEncryptionKey() {
  const key = await keytar.getPassword('Termius', 'localKey');
  if (!key) throw new Error('Termius encryption key not found — make sure you are logged in to Termius');
  return Buffer.from(key, 'base64');
}

async function decrypt(base64Data, key) {
  const data = Buffer.from(base64Data, 'base64');
  if (data[0] !== 4) return null;

  const nonce = data.slice(2, 26);
  const ciphertext = data.slice(26);

  try {
    const decrypted = sodium.crypto_secretbox_open_easy(
      new Uint8Array(ciphertext),
      new Uint8Array(nonce),
      new Uint8Array(key)
    );
    return Buffer.from(decrypted).toString('utf8');
  } catch {
    return null;
  }
}

async function extractAndDecrypt(key) {
  const dbPath = getDbPath();
  if (!fs.existsSync(dbPath)) {
    throw new Error(`Termius database not found at: ${dbPath}`);
  }

  const files = fs.readdirSync(dbPath).filter(f => f.endsWith('.log') || f.endsWith('.ldb'));

  // 'binary' (latin1) is lossless for arbitrary bytes — 'utf8' silently corrupts binary data
  let allData = '';
  files.forEach(f => {
    allData += fs.readFileSync(path.join(dbPath, f)).toString('binary');
  });

  const encrypted = [...new Set(allData.match(/BA[A-Za-z0-9+/=]{30,}/g) || [])];
  console.log(`Found ${encrypted.length} encrypted blocks`);

  const results = [];
  for (const e of encrypted) {
    const dec = await decrypt(e, key);
    if (dec) results.push(dec);
  }

  const pct = encrypted.length > 0 ? (results.length / encrypted.length * 100).toFixed(1) : '0.0';
  console.log(`Decrypted: ${results.length}/${encrypted.length} (${pct}%)`);
  return results;
}

// ==================== Parsing ====================

function parseDecryptedData(results) {
  const identitiesByUser = new Map();
  const keysByLabel = new Map();
  const keysById = new Map();
  const connections = [];
  const snippets = new Map();

  results.forEach(d => {
    if (!d.startsWith('{')) return;
    try {
      const obj = JSON.parse(d);

      if (obj.username !== undefined && obj.password !== undefined) {
        const mapKey = obj.label || obj.username;
        if (!identitiesByUser.has(mapKey) || obj.password) {
          identitiesByUser.set(mapKey, obj);
        }
      }

      if (obj.private_key && obj.label) {
        keysByLabel.set(obj.label, obj);
        if (obj.id) keysById.set(obj.id, obj);
      }

      if (obj.host && obj.user_name && obj.connection_type) {
        connections.push(obj);
      }

      if (obj.script && obj.label) {
        snippets.set(obj.label, obj);
      }
    } catch {}
  });

  return { identitiesByUser, keysByLabel, keysById, connections, snippets };
}

// ==================== Export ====================

function escapeCsv(v) {
  v = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;
  return `"${v.replace(/"/g, '""')}"`;
}

function buildHostConfig(data) {
  const { identitiesByUser, keysById, connections } = data;

  const hostMap = new Map();
  connections.forEach(conn => {
    const key = `${conn.host}:${conn.port}`;
    if (hostMap.has(key)) return;

    let password = '';
    identitiesByUser.forEach(id => {
      if (id.username === conn.user_name && id.password) password = id.password;
    });

    let keyName = '';
    if (conn.key_id) {
      const keyObj = keysById.get(conn.key_id);
      keyName = keyObj ? keyObj.label : `key_id:${conn.key_id}`;
    }

    hostMap.set(key, {
      host: conn.host,
      port: conn.port,
      label: conn.title || '',
      username: conn.user_name,
      password,
      keyName,
      os: conn.host_os_name || ''
    });
  });

  return hostMap;
}

function exportHostsCsv(hostMap) {
  let csv = 'Label,Host,Port,Username,Password,SSH_Key,OS\n';
  hostMap.forEach(h => {
    csv += [h.label, h.host, h.port, h.username, h.password, h.keyName, h.os].map(escapeCsv).join(',') + '\n';
  });
  fs.writeFileSync(path.join(OUTPUT_DIR, 'termius_hosts.csv'), BOM + csv);
  return hostMap.size;
}

function exportSshKeys(keysByLabel) {
  const keysDir = path.join(OUTPUT_DIR, 'ssh_keys');
  if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir, { mode: 0o700 });

  let count = 0;
  keysByLabel.forEach((k, label) => {
    if (!k.private_key) return;
    const safeName = label.replace(/[<>:"/\\|?*]/g, '_');

    const pemPath = path.join(keysDir, `${safeName}.pem`);
    fs.writeFileSync(pemPath, k.private_key, { mode: 0o600 });

    if (k.passphrase) {
      const ppPath = path.join(keysDir, `${safeName}.passphrase`);
      fs.writeFileSync(ppPath, k.passphrase, { mode: 0o600 });
    }
    count++;
  });
  return count;
}

function exportSnippets(snippets) {
  let csv = 'Label,Script\n';
  snippets.forEach((s, label) => {
    const script = (s.script || '').replace(/"/g, '""').replace(/\n/g, '\\n');
    csv += `"${label}","${script}"\n`;
  });
  fs.writeFileSync(path.join(OUTPUT_DIR, 'snippets.csv'), BOM + csv);
  return snippets.size;
}

// ==================== Main ====================

async function main() {
  console.log('=== Termius Data Exporter ===\n');

  await sodium.ready;

  console.log('[1/4] Retrieving encryption key...');
  const key = await getEncryptionKey();
  console.log('    ✓ Key retrieved\n');

  console.log('[2/4] Decrypting database...');
  const results = await extractAndDecrypt(key);
  console.log('');

  console.log('[3/4] Parsing data...');
  const data = parseDecryptedData(results);
  console.log(`    ✓ Identities: ${data.identitiesByUser.size}`);
  console.log(`    ✓ SSH keys:   ${data.keysByLabel.size}`);
  console.log(`    ✓ Connections:${data.connections.length}`);
  console.log(`    ✓ Snippets:   ${data.snippets.size}\n`);

  console.log('[4/4] Exporting...');
  const hostMap = buildHostConfig(data);
  const hostsCount = exportHostsCsv(hostMap);
  const keysCount = exportSshKeys(data.keysByLabel);
  const snippetsCount = exportSnippets(data.snippets);

  console.log(`    ✓ termius_hosts.csv (${hostsCount} hosts)`);
  console.log(`    ✓ ssh_keys/ (${keysCount} keys)`);
  console.log(`    ✓ snippets.csv (${snippetsCount} snippets)\n`);

  console.log('=== Export complete ===');
  console.log(`Output: ${OUTPUT_DIR}`);
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
