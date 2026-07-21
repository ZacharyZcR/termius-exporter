# How to Import (moving to a new computer)

1. **Export** on the old computer:
   ```bash
   npm install libsodium-wrappers keytar
   node termius-exporter.js
   ```
   This produces `termius_hosts.csv`, `ssh_keys/`, and `snippets.csv`.

2. **Zip and ship** the whole project folder (including `termius_hosts.csv`) to your new computer, then unzip it there.

3. **Run the importer** on the new computer:
   ```bash
   node termius-importer.js
   ```
   This reads `termius_hosts.csv` and creates `termius_import_ready.csv`.

4. **Import into Termius** on the new computer:
   - Go to **Hosts** → click **▼** next to "New Host" → **Import**
   - Select **CSV** → drag & drop `termius_import_ready.csv`
   - Review and click **Import**

5. Copy any needed private keys from `ssh_keys/` into Termius manually if not already linked.
