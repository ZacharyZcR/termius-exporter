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
const os = require('os');

const BOM = '\ufeff';

// Termius (Electron) \u5728\u4e0d\u540c\u7cfb\u7edf\u4e0b\u7684\u5e94\u7528\u6570\u636e\u6839\u76ee\u5f55
// macOS \u4e0a\u5206\u4e24\u79cd\u53d1\u884c\u7248\uff1a
//   - Mac App Store \u6c99\u76d2\u7248 (com.termius.mac)\uff1a\u6570\u636e\u5728 Containers \u5bb9\u5668\u5185
//   - \u5b98\u7f51\u76f4\u88c5\u7248\uff1a\u6570\u636e\u5728\u6807\u51c6\u7684 Application Support \u4e0b
const LEVELDB_SUBPATH = ['Termius', 'IndexedDB', 'file__0.indexeddb.leveldb'];

function getTermiusDbCandidates() {
  const home = os.homedir();

  switch (process.platform) {
    case 'win32': {
      const base = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
      return [path.join(base, ...LEVELDB_SUBPATH)];
    }
    case 'darwin': {
      const sandbox = path.join(home, 'Library', 'Containers', 'com.termius.mac',
        'Data', 'Library', 'Application Support');
      const standard = path.join(home, 'Library', 'Application Support');
      return [
        path.join(sandbox, ...LEVELDB_SUBPATH),   // App Store \u6c99\u76d2\u7248\uff08\u4f18\u5148\uff09
        path.join(standard, ...LEVELDB_SUBPATH),  // \u76f4\u88c5\u7248
      ];
    }
    default: { // linux \u7b49
      const base = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
      return [path.join(base, ...LEVELDB_SUBPATH)];
    }
  }
}

function getTermiusDbPath() {
  const candidates = getTermiusDbCandidates();
  return candidates.find(p => fs.existsSync(p)) || candidates[0];
}

const DB_PATH = getTermiusDbPath();
const OUTPUT_DIR = __dirname;

// ==================== 解密模块 ====================

// 不同发行版的密钥在钥匙串中的存放位置不同（服务名/账户名都可能不同），
// 因此先按已知组合尝试，失败后自动枚举候选服务下的账户来发现正确的密钥。
const KEY_SERVICES = ['Termius', 'com.termius.mac'];
const KEY_ACCOUNTS = ['localKey', 'TermiusKey', 'key', 'masterKey'];

// 把用户提供的字符串解析成 32 字节密钥（支持 base64 或 64 位 hex）
function parseManualKey(raw) {
  const s = raw.trim();

  // 64 位十六进制
  if (/^[0-9a-fA-F]{64}$/.test(s)) {
    return Buffer.from(s, 'hex');
  }

  // base64（容错：去掉空白）
  const buf = Buffer.from(s.replace(/\s+/g, ''), 'base64');
  if (buf.length === 32) return buf;

  throw new Error(
    `提供的密钥无法解析为 32 字节。\n` +
    `  得到 ${buf.length} 字节。请确认从钥匙串复制的是完整的 base64 值（约 44 个字符，通常以 "=" 结尾）。`
  );
}

async function getEncryptionKey() {
  // 0) 手动提供密钥：环境变量 TERMIUS_KEY 或命令行 --key=...
  const argKey = process.argv.find(a => a.startsWith('--key='));
  const manual = process.env.TERMIUS_KEY || (argKey && argKey.slice('--key='.length));
  if (manual) {
    const key = parseManualKey(manual);
    console.log('    ✓ 使用手动提供的密钥');
    return key;
  }

  // 1) 已知 (service, account) 组合的定向读取
  for (const service of KEY_SERVICES) {
    for (const account of KEY_ACCOUNTS) {
      const v = await keytar.getPassword(service, account);
      if (v) {
        console.log(`    ✓ 命中钥匙串项: service="${service}" account="${account}"`);
        return Buffer.from(v, 'base64');
      }
    }
  }

  // 2) 自动发现：列出候选服务下的所有账户
  const discovered = [];
  for (const service of KEY_SERVICES) {
    let creds = [];
    try {
      creds = await keytar.findCredentials(service);
    } catch {
      continue;
    }
    for (const { account, password } of creds) {
      discovered.push(`${service} / ${account}`);
      // 加密密钥通常是 base64 的 32 字节(=44 字符)随机串
      if (password && /^[A-Za-z0-9+/]{42,}={0,2}$/.test(password)) {
        console.log(`    ✓ 自动发现密钥: service="${service}" account="${account}"`);
        return Buffer.from(password, 'base64');
      }
    }
  }

  const found = discovered.length
    ? `\n钥匙串中发现以下相关项：\n  - ${discovered.join('\n  - ')}`
    : '\n未能通过脚本读取钥匙串（沙盒版 Termius 的密钥有 ACL 保护，node 进程无权读取）。';

  const manualHint =
    '\n\n请手动提供密钥：' +
    '\n  1) 打开“钥匙串访问 (Keychain Access)”，搜索 “Termius”' +
    '\n  2) 双击对应项 → 勾选“显示密码”，输入登录密码后复制该值（约 44 个字符的 base64）' +
    '\n  3) 重新运行：  TERMIUS_KEY=\'粘贴的值\' node termius-exporter.js' +
    '\n     或：        node termius-exporter.js --key=\'粘贴的值\'';

  throw new Error('未找到 Termius 加密密钥。' + found + manualHint);
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
  if (!fs.existsSync(DB_PATH)) {
    throw new Error(`未找到 Termius 数据库目录:\n  ${DB_PATH}\n请确认 Termius 已安装并至少登录过一次。`);
  }

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
