const $ = (id) => document.getElementById(id);
const room = decodeURIComponent(location.pathname.split('/room/')[1] || '').replace(/\/+$/, '');
$('title').textContent = room;

let myIdx = null;
let seed = null; // random local secret, held encrypted in the browser keystore (never leaves it)
let state = null;
let wasmReady = false;
const busy = new Set(); // in-flight action keys, to avoid duplicate posts while polling

(async function initWasm() {
  const go = new Go();
  const res = await WebAssembly.instantiateStreaming(fetch('/main.wasm'), go.importObject);
  go.run(res.instance);
  wasmReady = true;
})();

async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error);
  return data;
}

async function waitWasm() {
  while (!wasmReady) await new Promise((r) => setTimeout(r, 100));
}

function keystoreKey(account) { return `tsig-keystore-${account.toLowerCase()}-${room}`; }

// kekFor obtains the domain-bound EIP-712 unlock signature the keystore is encrypted under.
// Unlike a personal_sign of predictable text, another dapp cannot phish this exact typed-data
// signature without the wallet displaying this app's domain, and the signature alone is useless
// without the ciphertext stored in this browser.
async function kekFor(account) {
  const typed = JSON.stringify({
    domain: { name: 'Lighter Threshold Signatures PoC', version: '1' },
    primaryType: 'KeystoreUnlock',
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }],
      KeystoreUnlock: [{ name: 'purpose', type: 'string' }, { name: 'room', type: 'string' }],
    },
    message: { purpose: 'Unlock the local threshold-signature keystore', room },
  });
  return window.ethereum.request({ method: 'eth_signTypedData_v4', params: [account, typed] });
}

// unlockSeed decrypts the browser-local random seed for this (account, room), generating and
// storing a fresh one on first join. The wallet signature only unlocks the local keystore; the
// wallet alone cannot re-derive the seed.
async function unlockSeed(account) {
  const unlockSig = await kekFor(account);
  const stored = localStorage.getItem(keystoreKey(account));
  if (stored) {
    const ks = JSON.parse(stored);
    const out = window._tsKeystoreOpen(unlockSig, ks.blob);
    if (out.error) throw new Error(out.error);
    return { seed: out.seed, fresh: false };
  }
  const out = window._tsKeystoreSeal(unlockSig);
  if (out.error) throw new Error(out.error);
  localStorage.setItem(keystoreKey(account), JSON.stringify({ v: 1, blob: out.blob }));
  return { seed: out.seed, fresh: true };
}

function downloadKeystore(ks) {
  const blob = new Blob([ks], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `tsig-keystore-${room}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// showBackupModal prompts the participant to save the keystore as soon as it exists, since it
// lives only in this browser and is the only way to access the room from anywhere else.
function showBackupModal(account) {
  const ks = localStorage.getItem(keystoreKey(account));
  if (!ks) return;
  $('backupBlob').value = ks;
  $('backupModal').style.display = '';
  $('backupDownload').onclick = () => downloadKeystore(ks);
  $('backupCopy').onclick = async () => {
    await navigator.clipboard.writeText(ks);
    $('backupCopy').textContent = 'Copied ✓';
  };
  $('backupClose').onclick = () => { $('backupModal').style.display = 'none'; };
}

async function join() {
  try {
    const account = await window.connectWallet();
    if (!account) return;
    await waitWasm();
    // Unlock (or create) the browser-local keystore; the random seed inside is the root of all
    // per-room key material.
    const unlocked = await unlockSeed(account);
    seed = unlocked.seed;
    // Derive the per-room ceremony keys from the seed and bind them to the ETH address with a
    // personal_sign over the join statement; the server and every client verify it.
    const keys = window._tsKeys(seed, room);
    if (keys.error) throw new Error(keys.error);
    // Fetch the room policy directly and bind it into the signed statement, so a server that
    // later alters t or n cannot produce valid join signatures for the changed policy.
    const st = await api(`/api/rooms/${room}`);
    const roster = (st.allowed || []).join(',');
    if (roster && !st.allowed.includes(account.toLowerCase())) {
      throw new Error('your address is not on this room\'s allowlist');
    }
    const stmt = window._tsJoinStatement(room, st.threshold, st.total, roster, keys.authPk, keys.encPk, account).statement;
    const ethSig = await window.ethereum.request({ method: 'personal_sign', params: [stmt, account] });
    const data = await api(`/api/rooms/${room}/join`, {
      address: account, authPk: keys.authPk, encPk: keys.encPk, ethSig,
    });
    myIdx = data.idx;
    const mine = JSON.parse(localStorage.getItem('tsig-my-rooms') || '[]');
    if (!mine.includes(room)) localStorage.setItem('tsig-my-rooms', JSON.stringify([room, ...mine]));
    $('me').textContent = `you are participant #${myIdx}`;
    $('joinCard').style.display = 'none';
    if (unlocked.fresh) showBackupModal(account);
    refresh();
  } catch (e) {
    alert(e.message);
  }
}

$('join').onclick = join;

$('exportKs').onclick = async (ev) => {
  ev.preventDefault();
  const account = await window.connectWallet();
  if (!account) return;
  const ks = localStorage.getItem(keystoreKey(account));
  if (!ks) { alert('No keystore for this wallet + room in this browser yet.'); return; }
  downloadKeystore(ks);
};

$('importKs').onclick = async (ev) => {
  ev.preventDefault();
  const account = await window.connectWallet();
  if (!account) return;
  const raw = prompt('Paste the exported keystore JSON for this room:');
  if (!raw) return;
  try {
    const ks = JSON.parse(raw);
    if (!ks.blob) throw new Error('missing blob');
    localStorage.setItem(keystoreKey(account), JSON.stringify(ks));
    alert('Keystore imported — click join to unlock it.');
  } catch (e) {
    alert('Invalid keystore JSON: ' + e.message);
  }
};

window.onWalletDisconnect = () => {
  seed = null;
  myIdx = null;
  $('me').textContent = '';
  $('joinCard').style.display = '';
  render();
};

function mySharesFromState() {
  // Shares sent to me by every dealer: state.shares["from-myIdx"]
  const mine = {};
  for (const [key, share] of Object.entries(state.shares || {})) {
    const [from, to] = key.split('-').map(Number);
    if (to === myIdx) mine[from === 0 ? '0' : String(from)] = share;
  }
  return mine;
}

async function autoActions() {
  if (!wasmReady || !seed || myIdx === null || !state) return;

  // DKG: post my commitments + PoK + encrypted shares once everyone has joined.
  const me = (state.participants || []).find((p) => p.idx === myIdx);
  if (state.state === 'dkg' && me && !(me.commitments || []).length && !busy.has('dkg')) {
    busy.add('dkg');
    try {
      const encPks = {};
      for (const p of state.participants || []) encPks[String(p.idx)] = p.encPk;
      const out = window._tsDkg(seed, room, state.threshold, state.total, myIdx, encPks);
      if (out.error) throw new Error(out.error);
      await api(`/api/rooms/${room}/dkg`, {
        idx: myIdx, commitments: out.commitments, pok: out.pok, shares: out.shares, sig: out.sig,
      });
    } catch (e) {
      console.error('dkg failed', e);
      alert('DKG failed: ' + e.message);
    } finally {
      busy.delete('dkg');
    }
  }

  // After DKG completes, verify everything locally: every dealer's PoK, our decrypted shares
  // against their commitments, and the group public key (recomputed, not trusted from server).
  if (state.state === 'ready' && !window._roomVerified && !busy.has('verify')) {
    busy.add('verify');
    try {
      const allComms = {};
      const poks = {};
      for (const p of state.participants || []) {
        allComms[String(p.idx)] = p.commitments;
        poks[String(p.idx)] = p.pok;
      }
      const out = window._tsVerifyRoom(seed, room, myIdx, allComms, mySharesFromState(), poks);
      if (out.error) throw new Error(out.error);
      if (!out.ok) throw new Error('bad dealers: ' + out.bad.join(', '));
      if (out.groupPk !== state.groupPk) throw new Error('server group key mismatch!');
      window._roomVerified = true;
      render();
    } catch (e) {
      console.error('room verification failed', e);
      alert('Ceremony verification FAILED: ' + e.message);
    } finally {
      busy.delete('verify');
    }
  }

  // Signing: if a proposal's signer set is locked and I'm in it, auto-post my partial signature.
  for (const p of state.proposals || []) {
    const set = p.signerSet || [];
    if (p.status !== 'signing' || !set.includes(myIdx)) continue;
    if (p.partials && p.partials[String(myIdx)]) continue;
    const key = 'partial-' + p.id;
    if (busy.has(key)) continue;
    busy.add(key);
    try {
      await signingLock(p.id, async () => {
        // One-shot nonces: only sign with the pair stored at commit time, and never sign twice.
        if (localStorage.getItem(signedKey(p.id))) return;
        const nonces = localStorage.getItem(nonceKey(p.id));
        if (!nonces) {
          console.error(`no stored nonces for proposal ${p.id} (state lost?) — refusing to sign`);
          return;
        }
        const out = window._tsSignPartial(seed, room, p.id, p.message, myIdx, set, mySharesFromState(), p.commits, nonces);
        if (out.error) throw new Error(out.error);
        localStorage.setItem(signedKey(p.id), '1');
        localStorage.removeItem(nonceKey(p.id));
        await api(`/api/proposals/${p.id}/partial`, { idx: myIdx, s: out.s, sig: out.sig });
      });
    } catch (e) {
      console.error('partial failed', e);
    } finally {
      busy.delete(key);
    }
  }
}

function nonceKey(id) { return `tsig-nonces-${room}-${id}`; }
function signedKey(id) { return `tsig-signed-${room}-${id}`; }

// signingLock serializes the read-compute-write sequence around a proposal's nonce state across
// every tab of this identity, not just within one tab: navigator.locks is a per-origin mutex the
// browser enforces across tabs, so two tabs can never both pass the "not yet signed" check and
// then both consume the same one-shot nonce pair (which would leak the signing share).
function signingLock(id, fn) {
  const key = `tsig-sign-${room}-${(window.walletAccount || 'anon').toLowerCase()}-${id}`;
  return navigator.locks.request(key, fn);
}

async function signProposal(id) {
  if (!seed || myIdx === null) { alert('Join the room first'); return; }
  await signingLock(id, async () => {
    if (localStorage.getItem(signedKey(id))) { alert('You already signed this proposal.'); return; }
    if (localStorage.getItem(nonceKey(id))) { refresh(); return; } // commit already posted
    const out = window._tsSignCommit(seed, room, id, myIdx);
    if (out.error) { alert(out.error); return; }
    localStorage.setItem(nonceKey(id), out.nonces);
    try {
      await api(`/api/proposals/${id}/commit`, { idx: myIdx, d: out.d, e: out.e, sig: out.sig });
    } catch (e) {
      localStorage.removeItem(nonceKey(id));
      alert(e.message);
    }
  });
  refresh();
}

async function executeProposal(id) {
  try {
    const res = await api(`/api/proposals/${id}/execute`, {});
    if (!res.valid) alert('Aggregated signature INVALID: ' + (res.verifyError || ''));
  } catch (e) {
    alert(e.message);
  }
  refresh();
}

$('propose').onclick = async () => {
  const message = $('msgInput').value.trim();
  if (!message) return;
  if (!/^(0x)?[0-9a-fA-F]{80}$/.test(message)) {
    alert('Proposal must be a 40-byte Lighter transaction hash in hex (0x optional)');
    return;
  }
  if (myIdx === null) { alert('Join the room first'); return; }
  try {
    const out = window._tsSignPropose(seed, room, message, myIdx);
    if (out.error) throw new Error(out.error);
    await api(`/api/rooms/${room}/proposals`, { message, proposer: myIdx, nonce: out.nonce, sig: out.sig });
    $('msgInput').value = '';
    refresh();
  } catch (e) {
    alert(e.message);
  }
};

// proposerBadge verifies the proposal's auth-key signature against the proposer's stored
// public key, so a server cannot forge proposals attributed to another participant.
function proposerBadge(p) {
  if (!window._tsVerifyProposal) return '';
  if (!p.sig) return '<span class="warn">⚠ unsigned proposal</span>';
  // Proposals from before replay-protection nonces were added were signed over a payload with
  // no nonce segment at all; they cannot be re-verified against the current payload format.
  if (!p.nonce) return '<span class="warn">⚠ predates replay protection, not independently verifiable</span>';
  const proposer = (state.participants || []).find((q) => q.idx === p.proposer);
  if (!proposer) return '<span class="bad">✘ unknown proposer</span>';
  const out = window._tsVerifyProposal(room, p.message, p.proposer, p.nonce, p.sig, proposer.authPk);
  return out.ok ? '<span class="ok">✓ verified</span>' : '<span class="bad">✘ invalid proposer signature</span>';
}

// dkgFingerprint digests the public DKG transcript into five words. Participants compare them
// out-of-band (call, chat) before signing anything: a server showing different transcripts to
// different clients produces different words.
function dkgFingerprint() {
  if (!wasmReady || !state || state.state !== 'ready') return '';
  const parts = {};
  for (const p of state.participants || []) {
    if (!(p.commitments || []).length) return '';
    parts[String(p.idx)] = {
      address: p.address, authPk: p.authPk, encPk: p.encPk, commitments: p.commitments, pok: p.pok,
    };
  }
  const out = window._tsDkgFingerprint(room, state.threshold, state.total, (state.allowed || []).join(','), parts);
  return out.fp || '';
}

function proposalFingerprint(p, set) {
  if (!wasmReady || !set.length) return '';
  const out = window._tsProposalFingerprint(room, p.id, p.message, set, p.commits || {});
  return out.fp || '';
}

const stateLabels = { joining: 'waiting for participants', dkg: 'key generation', ready: 'ready to sign' };

function render() {
  if (!state) return;
  const joined = (state.participants || []).length;
  $('statusChip').className = 'status-chip ' + state.state;
  $('status').textContent =
    `${state.threshold}-of-${state.total} · ${stateLabels[state.state] || state.state}` +
    (state.state === 'joining' ? ` (${joined}/${state.total})` : '') +
    ((state.allowed || []).length ? ' · allowlisted' : '');

  $('participants').innerHTML = (state.participants || [])
    .map((p) => {
      const done = (p.commitments || []).length ? ' done' : '';
      const you = p.idx === myIdx ? ' · you' : '';
      let badge = '';
      if (wasmReady) {
        const roster = (state.allowed || []).join(',');
        const listed = !roster || state.allowed.includes(p.address.toLowerCase());
        const v = window._tsVerifyJoin(room, state.threshold, state.total, roster, p.authPk, p.encPk, p.address, p.ethSig);
        if (!listed) v.ok = false;
        badge = v.ok ? ' <span class="ok" title="join statement signature verified">✓</span>'
                     : ' <span class="bad" title="join statement signature INVALID">✘</span>';
      }
      return `<span class="pill${done}"><span class="dot"></span>#${p.idx} ${p.address}${you}${badge}</span>`;
    })
    .join(' ') || '<span class="muted">nobody yet — share the room code</span>';

  const verifiedNote = window._roomVerified
    ? ' <span class="ok" style="font-size:12px">✓ verified locally (PoKs, shares, group key)</span>'
    : '';
  const dkgFp = dkgFingerprint();
  const fpNote = dkgFp
    ? `<p class="hint" style="margin:10px 0 4px">Ceremony fingerprint — read these five words to the other
       participants out-of-band; everyone must see the same ones</p><span class="mono warn">${dkgFp}</span>`
    : '';
  $('groupPk').innerHTML = state.groupPk
    ? `<p class="hint" style="margin:14px 0 4px">Group public key${verifiedNote}</p><span class="mono ok">${state.groupPk}</span>${fpNote}`
    : '';

  $('proposeCard').style.display = state.state === 'ready' ? '' : 'none';

  $('proposals').innerHTML = (state.proposals || []).map((p) => {
    const set = p.signerSet || [];
    const committed = Object.keys(p.commits || {});
    const partials = Object.keys(p.partials || {});
    const canSign = p.status === 'signing' && !set.length && myIdx !== null && !committed.includes(String(myIdx));
    const canExec = p.status === 'signing' && set.length && partials.length >= set.length;
    let statusHTML;
    let progress = 0;
    if (p.status === 'executed') {
      statusHTML = p.valid
        ? `<span class="ok">✔ executed — signature VALID</span>`
        : `<span class="bad">✘ executed — signature INVALID</span>`;
      progress = 100;
    } else if (set.length) {
      const fp = proposalFingerprint(p, set);
      statusHTML = `<span class="warn">signer set locked [${set.join(', ')}]</span> <span class="muted">· partials ${partials.length}/${set.length}</span>` +
        (fp ? ` <span class="muted">· fingerprint</span> <span class="mono warn">${fp}</span>` : '');
      progress = 50 + 50 * (partials.length / set.length);
    } else {
      statusHTML = `<span class="muted">waiting for signers · committed [${committed.join(', ')}] — need ${state.threshold}</span>`;
      progress = 50 * (committed.length / state.threshold);
    }
    const sigHTML = p.status === 'executed' && p.valid
      ? `<div class="sig"><p class="hint" style="margin:8px 0 4px">Aggregated Schnorr signature (s ‖ e)</p><span class="mono">${p.finalSig}</span></div>`
      : '';
    return `<div class="proposal">
      <div>
        <div class="msg">#${p.id} “${p.message}”</div>
        <div class="meta">proposed by #${p.proposer} ${proposerBadge(p)} · ${p.createdAt}</div>
        <div style="margin-top:8px">${statusHTML}</div>
        <div class="progress"><div style="width:${progress}%"></div></div>
      </div>
      <div class="actions">
        ${canSign ? `<button class="green" onclick="signProposal(${p.id})">Sign</button>` : ''}
        ${canExec ? `<button onclick="executeProposal(${p.id})">Execute</button>` : ''}
      </div>
      ${sigHTML}
    </div>`;
  }).join('');
}

async function refresh() {
  try {
    state = await api(`/api/rooms/${room}`);
    render();
    await autoActions();
  } catch (e) {
    $('status').textContent = e.message;
  }
}

refresh();
setInterval(refresh, 2000);
