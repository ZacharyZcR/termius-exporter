#!/usr/bin/env node
/**
 * Termius 数据一键导出工具
 *
 * 功能：从本地 Termius 数据库提取并解密所有数据
 * 输出：full_host_config.csv, ssh_keys/, snippets.csv
 *
 * 依赖：npm install libsodium-wrappers keytar
 */

const sodium = require('libsodium-wrappers');
const keytar = require('keytar');
const fs = require('fs');
const path = require('path');

const BOM = '\ufeff';
const DB_PATH = path.join(process.env.APPDATA, 'Termius/IndexedDB/file__0.indexeddb.leveldb/');
const OUTPUT_DIR = __dirname;

// ==================== 解密模块 ====================

async function getEncryptionKey() {
  const key = await keytar.getPassword('Termius', 'localKey');
  if (!key) throw new Error('未找到 Termius 加密密钥，请确保已登录 Termius');
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
  const files = fs.readdirSync(DB_PATH).filter(f => f.endsWith('.log') || f.endsWith('.ldb'));

  let allData = '';
  files.forEach(f => {
    allData += fs.readFileSync(path.join(DB_PATH, f)).toString('utf8');
  });

  const encrypted = [...new Set(allData.match(/BA[A-Za-z0-9+/=]{30,}/g) || [])];
  console.log(`找到 ${encrypted.length} 个加密块`);

  const results = [];
  for (const e of encrypted) {
    const dec = await decrypt(e, key);
    if (dec) results.push(dec);
  }

  console.log(`成功解密: ${results.length}/${encrypted.length} (${(results.length/encrypted.length*100).toFixed(1)}%)`);
  return results;
}

// ==================== 数据解析模块 ====================

function parseDecryptedData(results) {
  const identitiesByUser = new Map();
  const keysByLabel = new Map();
  const connections = [];
  const snippets = new Map();

  results.forEach(d => {
    if (!d.startsWith('{')) return;
    try {
      const obj = JSON.parse(d);

      // 身份认证 (带密码)
      if (obj.username !== undefined && obj.password !== undefined) {
        const key = obj.label || obj.username;
        if (!identitiesByUser.has(key) || obj.password) {
          identitiesByUser.set(key, obj);
        }
      }

      // SSH 密钥
      if (obj.private_key && obj.label) {
        keysByLabel.set(obj.label, obj);
      }

      // 连接记录
      if (obj.host && obj.user_name && obj.connection_type) {
        connections.push(obj);
      }

      // 代码片段
      if (obj.script && obj.label) {
        snippets.set(obj.label, obj);
      }
    } catch {}
  });

  return { identitiesByUser, keysByLabel, connections, snippets };
}

// ==================== 导出模块 ====================

function buildHostConfig(data) {
  const { identitiesByUser, keysByLabel, connections } = data;

  // 统计 key_id 使用情况
  const keyIdUsage = new Map();
  connections.forEach(conn => {
    if (conn.key_id) {
      if (!keyIdUsage.has(conn.key_id)) {
        keyIdUsage.set(conn.key_id, { count: 0, hosts: [] });
      }
      const info = keyIdUsage.get(conn.key_id);
      info.count++;
    }
  });

  // 按使用频率排序，建立 key_id -> label 映射
  const keyIdList = [...keyIdUsage.entries()].sort((a, b) => b[1].count - a[1].count);
  const keyLabelList = [...keysByLabel.keys()];

  // 构建主机配置
  const hostMap = new Map();
  connections.forEach(conn => {
    const key = `${conn.host}:${conn.port}`;
    if (!hostMap.has(key)) {
      // 查找密码
      let password = '';
      identitiesByUser.forEach((id) => {
        if (id.username === conn.user_name && id.password) {
          password = id.password;
        }
      });

      // 查找密钥名称
      let keyName = '';
      if (conn.key_id) {
        const idx = keyIdList.findIndex(e => e[0] === conn.key_id);
        if (idx >= 0 && idx < keyLabelList.length) {
          keyName = keyLabelList[idx];
        } else {
          keyName = `key_id:${conn.key_id}`;
        }
      }

      hostMap.set(key, {
        host: conn.host,
        port: conn.port,
        label: conn.title || '',
        username: conn.user_name,
        password: password,
        keyName: keyName,
        os: conn.host_os_name || ''
      });
    }
  });

  return hostMap;
}

function exportHostsCsv(hostMap) {
  let csv = 'Label,Host,Port,Username,Password,SSH_Key,OS\n';
  hostMap.forEach(h => {
    csv += `"${h.label}","${h.host}","${h.port}","${h.username}","${h.password}","${h.keyName}","${h.os}"\n`;
  });
  fs.writeFileSync(path.join(OUTPUT_DIR, 'L00t.csv'), BOM + csv);
  return hostMap.size;
}

function exportSshKeys(keysByLabel) {
  const keysDir = path.join(OUTPUT_DIR, 'ssh_keys');
  if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir);

  let count = 0;
  keysByLabel.forEach((k, label) => {
    if (k.private_key) {
      const safeName = label.replace(/[<>:"/\\|?*]/g, '_');
      fs.writeFileSync(path.join(keysDir, `${safeName}.pem`), k.private_key);

      // 保存密钥信息
      if (k.passphrase) {
        fs.writeFileSync(path.join(keysDir, `${safeName}.passphrase`), k.passphrase);
      }
      count++;
    }
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

// ==================== 主程序 ====================

async function main() {
  console.log('=== Termius 数据导出工具 ===\n');

  // 初始化
  await sodium.ready;

  // 获取密钥
  console.log('[1/4] 获取加密密钥...');
  const key = await getEncryptionKey();
  console.log('    ✓ 密钥获取成功\n');

  // 解密数据
  console.log('[2/4] 解密数据库...');
  const results = await extractAndDecrypt(key);
  console.log('');

  // 解析数据
  console.log('[3/4] 解析数据...');
  const data = parseDecryptedData(results);
  console.log(`    ✓ 身份认证: ${data.identitiesByUser.size}`);
  console.log(`    ✓ SSH 密钥: ${data.keysByLabel.size}`);
  console.log(`    ✓ 连接记录: ${data.connections.length}`);
  console.log(`    ✓ 代码片段: ${data.snippets.size}\n`);

  // 导出
  console.log('[4/4] 导出文件...');
  const hostMap = buildHostConfig(data);
  const hostsCount = exportHostsCsv(hostMap);
  const keysCount = exportSshKeys(data.keysByLabel);
  const snippetsCount = exportSnippets(data.snippets);

  console.log(`    ✓ L00t.csv (${hostsCount} 条主机配置)`);
  console.log(`    ✓ ssh_keys/ (${keysCount} 个密钥)`);
  console.log(`    ✓ snippets.csv (${snippetsCount} 个代码片段)\n`);

  console.log('=== 导出完成 ===');
  console.log(`输出目录: ${OUTPUT_DIR}`);
}

main().catch(err => {
  console.error('错误:', err.message);
  process.exit(1);
});
