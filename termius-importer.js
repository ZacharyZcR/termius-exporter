#!/usr/bin/env node
/**
 * Termius Importer - Matches latest Termius CSV format
 * Source: termius_hosts.csv (from exporter) → termius_import_ready.csv
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const INPUT_CSV = path.join(__dirname, 'termius_hosts.csv');
const OUTPUT_CSV = path.join(__dirname, 'termius_import_ready.csv');

async function main() {
  if (!fs.existsSync(INPUT_CSV)) {
    console.error('❌ termius_hosts.csv not found!');
    console.error('Please copy it from your Intel Mac to this folder.');
    process.exit(1);
  }

  console.log('🔄 Converting to new Termius import format...\n');

  let output = 'Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password\n';
  let count = 0;

  const rl = readline.createInterface({
    input: fs.createReadStream(INPUT_CSV)
  });

  let isHeader = true;
  for await (const line of rl) {
    if (isHeader) { isHeader = false; continue; }

    const fields = parseCSVLine(line);
    if (fields.length < 2) continue;

    const [label, host, port, username, password, sshKey] = fields.map(f => (f || '').trim());

    // Map to new format
    output += [
      "",                    // Groups (empty for now)
      `"${label}"`,          // Label
      "",                    // Tags
      `"${host}"`,           // Hostname/IP
      "ssh",                 // Protocol
      port || "22",          // Port
      `"${username}"`,       // Username
      `"${password}"`        // Password
    ].join(',') + '\n';

    count++;
  }

  fs.writeFileSync(OUTPUT_CSV, output);

  console.log(`✅ Success! Created ${OUTPUT_CSV} with ${count} hosts.`);
  console.log('\nImport Instructions:');
  console.log('1. Open Termius on your M1 Mac');
  console.log('2. Go to Hosts → Click ▼ next to "New Host" → Import');
  console.log('3. Select CSV → Drag & drop termius_import_ready.csv');
  console.log('4. Review and click Import');
}

function parseCSVLine(line) {
  return line.match(/(".*?"|[^",]+)(?=\s*,|\s*$)/g)
    ?.map(f => f.replace(/^"|"$/g, '').replace(/""/g, '"')) || [];
}

main().catch(err => console.error('Error:', err.message));