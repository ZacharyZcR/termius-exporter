#!/usr/bin/env node
/**
 * Termius Importer - Matches latest Termius CSV format
 * Source: termius_hosts.csv (from exporter) → termius_import_ready.csv
 */

const fs = require('fs');
const path = require('path');

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

  const rows = parseCSV(fs.readFileSync(INPUT_CSV, 'utf8').replace(/^\uFEFF/, ''));
  for (const fields of rows.slice(1)) {
    if (fields.length < 2 || fields.every(field => !field)) continue;

    const [label, host, port, username, password] = fields.map(f => (f || '').trim());

    // Map to new format
    output += [
      "",                    // Groups (empty for now)
      escapeCSV(label),      // Label
      "",                    // Tags
      escapeCSV(host),       // Hostname/IP
      "ssh",                 // Protocol
      port || "22",          // Port
      escapeCSV(username),   // Username
      escapeCSV(password)    // Password
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

function parseCSV(input) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;

  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (char === '"') {
      if (quoted && input[i + 1] === '"') {
        field += '"';
        i++;
      } else {
        quoted = !quoted;
      }
    } else if (char === ',' && !quoted) {
      row.push(field);
      field = '';
    } else if ((char === '\n' || char === '\r') && !quoted) {
      if (char === '\r' && input[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += char;
    }
  }

  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function escapeCSV(value) {
  return `"${String(value || '').replace(/"/g, '""')}"`;
}

main().catch(err => console.error('Error:', err.message));
