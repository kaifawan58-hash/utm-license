#!/usr/bin/env node
// Kill switch list for Typing Tutor. Zero dependencies, Node 20 or newer.
//   node revocations.mjs add  --key owner-private-key.pem --id UTM-XXXX-XXXX [--id ...] --out revocations.json
//   node revocations.mjs remove --key owner-private-key.pem --id UTM-XXXX-XXXX --out revocations.json
//   node revocations.mjs init --key owner-private-key.pem --out revocations.json   (empty list, for the online check)
//   node revocations.mjs show --file revocations.json
// "add" and "remove" read the existing --out file (if any), change it, sign it with your private key and write it back.
// Upload the file to the https address set in src/license/revocationUrl.ts. The License ID is printed when you issue a key.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { publicKeyOf } from '../../src/license/format.mjs';
import { normalizeLicenseId, readUnverified, signRevocations, verifyRevocations } from '../../src/license/revocation.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const out = { _: [], id: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const name = a.slice(2);
    const next = argv[i + 1];
    const value = next === undefined || next.startsWith('--') ? true : (i++, next);
    if (name === 'id') out.id.push(String(value)); else out[name] = value;
  }
  return out;
}
const fail = (m) => { console.error(`Error: ${m}`); process.exit(1); };
const need = (a, n) => (typeof a[n] === 'string' && a[n] !== '' ? a[n] : fail(`Missing --${n}`));

const args = parseArgs(process.argv.slice(2));
const cmd = args._[0];

function embeddedPublicKey() {
  const m = /PUBLIC_KEY_SPKI_BASE64\s*=\s*'([A-Za-z0-9+/=]+)'/.exec(fs.readFileSync(path.join(here, '..', '..', 'src', 'license', 'publicKey.ts'), 'utf8'));
  return m ? m[1] : fail('Could not read the public key from src/license/publicKey.ts');
}

if (cmd === 'init') {
  // Makes a signed empty list, enough for the online check. An existing list is kept as it is.
  const pem = fs.readFileSync(need(args, 'key'), 'utf8');
  const out = need(args, 'out');
  if (publicKeyOf(pem) !== embeddedPublicKey()) fail('That private key does not match the public key in the app, so the app would ignore this list.');
  const existing = fs.existsSync(out) ? readUnverified(fs.readFileSync(out, 'utf8')) : null;
  fs.writeFileSync(out, signRevocations(pem, existing ? existing.ids : [], Math.max(Date.now(), (existing?.issuedAt ?? 0) + 1)), 'utf8');
  console.log(`Written to ${out}. The list has ${existing ? existing.ids.length : 0} withdrawn license(s).`);
} else if (cmd === 'add' || cmd === 'remove') {
  const pem = fs.readFileSync(need(args, 'key'), 'utf8');
  const out = need(args, 'out');
  if (args.id.length === 0) fail('Give at least one --id.');
  // The key you sign with must match the public key inside the app, or the app would ignore the list.
  if (publicKeyOf(pem) !== embeddedPublicKey()) fail('That private key does not match the public key in the app, so the app would ignore this list.');
  const existing = fs.existsSync(out) ? readUnverified(fs.readFileSync(out, 'utf8')) : null;
  const set = new Set(existing ? existing.ids : []);
  for (const id of args.id.map(normalizeLicenseId)) { if (cmd === 'add') set.add(id); else set.delete(id); }
  // The time must go up with every version: the app refuses an older list.
  const issuedAt = Math.max(Date.now(), (existing?.issuedAt ?? 0) + 1);
  fs.writeFileSync(out, signRevocations(pem, [...set], issuedAt), 'utf8');
  console.log(`${cmd === 'add' ? 'Added' : 'Removed'} ${args.id.length} id(s). The list now has ${set.size} withdrawn license(s). Written to ${out}`);
  console.log('Upload that file to the address in src/license/revocationUrl.ts. Apps pick it up within about 6 hours of being online.');
} else if (cmd === 'show') {
  const file = need(args, 'file');
  const r = verifyRevocations(fs.readFileSync(file, 'utf8'), embeddedPublicKey());
  if (!r.ok) fail(`The list is not valid for this app (${r.reason}).`);
  console.log(`Valid list from ${new Date(r.issuedAt).toISOString()} with ${r.ids.length} withdrawn license(s):`);
  for (const id of r.ids) console.log(`  ${id}`);
} else {
  console.log('Usage:\n  node revocations.mjs add --key <private.pem> --id <LICENSE-ID> [--id ...] --out revocations.json\n  node revocations.mjs remove --key <private.pem> --id <LICENSE-ID> --out revocations.json\n  node revocations.mjs show --file revocations.json');
  process.exit(cmd ? 1 : 0);
}
