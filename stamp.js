const API = 'stamp.formisworkk.workers.dev';

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

class Sha256 {
  constructor() {
    this.h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    this.w = new Uint32Array(64);
    this.buffer = new Uint8Array(64);
    this.fill = 0;
    this.length = 0;
  }

  block(p, o) {
    const w = this.w;

    for (let i = 0; i < 16; i++) w[i] = (p[o + 4 * i] << 24) | (p[o + 4 * i + 1] << 16) | (p[o + 4 * i + 2] << 8) | p[o + 4 * i + 3];

    for (let i = 16; i < 64; i++) {
      const a = w[i - 15];
      const b = w[i - 2];
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }

    let [a, b, c, d, e, f, g, h] = this.h;

    for (let i = 0; i < 64; i++) {
      const s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const t1 = (h + s1 + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
      const s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }

    const next = [a, b, c, d, e, f, g, h];
    for (let i = 0; i < 8; i++) this.h[i] = (this.h[i] + next[i]) | 0;
  }

  update(data) {
    this.length += data.length;
    let offset = 0;

    if (this.fill) {
      const take = Math.min(64 - this.fill, data.length);
      this.buffer.set(data.subarray(0, take), this.fill);
      this.fill += take;
      offset = take;

      if (this.fill === 64) {
        this.block(this.buffer, 0);
        this.fill = 0;
      }
    }

    for (; offset + 64 <= data.length; offset += 64) this.block(data, offset);

    if (offset < data.length) {
      this.buffer.set(data.subarray(offset), 0);
      this.fill = data.length - offset;
    }
  }

  digest() {
    const bits = this.length * 8;
    const padLength = (this.fill < 56 ? 56 : 120) - this.fill;
    const tail = new Uint8Array(padLength + 8);
    const view = new DataView(tail.buffer);

    tail[0] = 0x80;
    view.setUint32(padLength, Math.floor(bits / 2 ** 32));
    view.setUint32(padLength + 4, bits >>> 0);
    this.update(tail);

    return Array.from(this.h, (word) => (word >>> 0).toString(16).padStart(8, '0')).join('');
  }
}

async function hashBlob(blob, onProgress) {
  const hasher = new Sha256();
  const chunk = 4 * 1024 * 1024;

  for (let start = 0; start < blob.size; start += chunk) {
    hasher.update(new Uint8Array(await blob.slice(start, start + chunk).arrayBuffer()));
    onProgress?.(Math.min(1, (start + chunk) / blob.size));
  }

  onProgress?.(1);
  return hasher.digest();
}

const state = { parent: '' };
const $ = (id) => document.getElementById(id);
const statusNode = $('status');
const resultNode = $('result');

function make(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function formatTime(iso) {
  return `${new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })} UTC`;
}

function formatDay(iso) {
  return new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }).toUpperCase();
}

function formatSize(bytes) {
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function setStatus(text, mode = '', progress = null) {
  statusNode.hidden = !text;
  statusNode.className = `status ${mode ? `is-${mode}` : ''}`.trim();
  statusNode.textContent = text;

  if (progress !== null) {
    const bar = make('span', 'bar');
    const fill = make('i');
    fill.style.width = `${Math.round(progress * 100)}%`;
    bar.append(fill);
    statusNode.append(bar);
  }
}

function fromBase64(text) {
  return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
}

async function api(path, options) {
  const response = await fetch(`${API}${path}`, options);
  const data = await response.json().catch(() => ({}));

  if (!response.ok) throw new Error(data.error || 'Something went wrong. Please try again.');
  return data;
}

function copyButton(value) {
  const button = make('button', '', 'Copy');
  button.type = 'button';

  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(value);
      button.textContent = 'Copied';
    } catch {
      button.textContent = 'Select';
    }

    setTimeout(() => {
      button.textContent = 'Copy';
    }, 1600);
  });

  return button;
}

function fact(label, value, copy = false) {
  const wrap = make('div', 'fact');
  const row = make('div');
  row.append(make('code', '', value));
  if (copy) row.append(copyButton(value));
  wrap.append(make('span', '', label), row);
  return wrap;
}

function sealSvg(iso, fresh) {
  const wrap = make('div');
  wrap.innerHTML = `<svg class="seal${fresh ? ' is-new' : ''}" viewBox="0 0 200 200" role="img" aria-label="Stamped seal">
    <defs><path id="ring" d="M100,100 m-80,0 a80,80 0 1,1 160,0 a80,80 0 1,1 -160,0"/></defs>
    <circle cx="100" cy="100" r="95" stroke-width="3"/>
    <circle cx="100" cy="100" r="66" stroke-width="1.5"/>
    <text class="seal__ring"><textPath href="#ring" textLength="496" lengthAdjust="spacing">STAMPED · EXISTED · UNCHANGED · PROVEN ·</textPath></text>
    <text class="seal__big" x="100" y="102">STAMPED</text>
    <text class="seal__date" x="100" y="124">${formatDay(iso)}</text>
  </svg>`;
  return wrap.firstElementChild;
}

function createChecker(record) {
  const block = make('div', 'block');
  const label = make('label', 'checker');
  const input = make('input');
  const verdict = make('div');

  input.type = 'file';
  label.append(input, make('strong', '', record.kind === 'site' ? 'Drop the snapshot file to check it' : 'Drop a file to check it'), make('small', '', 'It is compared in your browser. Nothing is uploaded.'));
  block.append(make('h3', '', 'Is it the same file?'), label, verdict);

  label.addEventListener('dragover', (event) => {
    event.preventDefault();
    label.classList.add('is-over');
  });
  label.addEventListener('dragleave', () => label.classList.remove('is-over'));

  async function check(file) {
    label.classList.remove('is-over');
    verdict.replaceChildren();
    verdict.className = '';

    const hash = await hashBlob(file);
    const same = hash === record.hash;

    verdict.className = `verdict${same ? '' : ' is-bad'}`;
    verdict.textContent = same
      ? `Match. This file is identical to the one stamped on ${formatTime(record.time || record.createdAt)}.`
      : 'No match. This file is different from the stamped one, even by a single byte.';
  }

  label.addEventListener('drop', (event) => {
    event.preventDefault();
    if (event.dataTransfer.files[0]) check(event.dataTransfer.files[0]);
  });
  input.addEventListener('change', () => input.files[0] && check(input.files[0]));

  return block;
}

async function createTimeline(record) {
  const chain = [record];

  try {
    while (chain.at(-1).parent && chain.length < 12) chain.push(await api(`/api/stamp/${chain.at(-1).parent}`));
  } catch {
    return null;
  }

  if (chain.length < 2) return null;

  const block = make('div', 'block');
  const list = make('ol', 'timeline');

  chain.forEach((item, index) => {
    const row = make('li', index === 0 ? 'is-current' : '');
    const link = make('a', '', item.id);
    link.href = `?s=${item.id}`;
    row.append(link, make('span', '', `${formatTime(item.time || item.createdAt)}${item.label ? ` · ${item.label}` : ''}`));
    list.append(row);
  });

  block.append(make('h3', '', `Version history (${chain.length})`), list);
  return block;
}

function createEmbed(record) {
  const block = make('div', 'block embed');
  const page = `${location.origin}${location.pathname}?s=${record.id}`;
  const image = make('img');
  const code = make('code', '', `<a href="${page}"><img src="${API}/b/${record.id}.svg" alt="Stamped ${formatDay(record.time || record.createdAt)}"></a>`);

  image.src = `${API}/b/${record.id}.svg`;
  image.alt = 'Stamp badge';
  block.append(make('h3', '', 'Show it on your site'), image, code, copyButton(code.textContent));
  return block;
}

function renderCertificate(record, options = {}) {
  const cert = make('article', 'cert');
  const when = record.time || record.createdAt;
  const title = record.kind === 'site' ? record.site.title || record.site.finalUrl : record.label || 'This file existed.';
  const page = `${location.origin}${location.pathname}?s=${record.id}`;
  const facts = make('div', 'facts');
  const actions = make('div', 'actions');

  facts.append(fact('Fingerprint (SHA-256)', record.hash, true), fact('Certificate link', page, true));

  if (record.kind === 'site') facts.prepend(fact('Web address', record.site.finalUrl || record.site.url));
  if (record.authority) facts.append(fact('Time authority', `${record.authority}${record.hasOts ? ' + Bitcoin calendars' : ''}`));

  if (record.hasTsr) {
    const tsr = make('a', '', 'Download .tsr proof');
    tsr.href = `${API}/api/proof/${record.id}/tsr`;
    actions.append(tsr);
  }

  if (record.hasOts) {
    const ots = make('a', '', 'Download .ots proof');
    ots.href = `${API}/api/proof/${record.id}/ots`;
    actions.append(ots);
  }

  if (options.snapshot) {
    const snapshot = make('a', '', 'Download the page snapshot');
    snapshot.href = URL.createObjectURL(options.snapshot);
    snapshot.download = `snapshot-${record.id}.html`;
    actions.append(snapshot);
  }

  const another = make('button', '', 'Stamp a new version');
  another.type = 'button';
  another.addEventListener('click', () => startVersion(record));
  actions.append(another);

  cert.append(
    sealSvg(when, options.fresh),
    make('p', 'cert__eyebrow', `Certificate · ${record.id}`),
    make('h2', '', title),
    make('p', 'cert__time', formatTime(when)),
    facts,
    actions,
    createChecker(record)
  );

  resultNode.hidden = false;
  resultNode.replaceChildren(cert);

  createTimeline(record).then((timeline) => timeline && cert.append(timeline));
  cert.append(createEmbed(record));
  return cert;
}

function startVersion(record) {
  state.parent = record.id;
  $('parent-text').textContent = `Stamping a new version of ${record.id}`;
  $('parent').hidden = false;
  $('tool').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

$('parent-cancel').addEventListener('click', () => {
  state.parent = '';
  $('parent').hidden = true;
});

async function createStamp(hash, payload, snapshot) {
  setStatus('Asking the time authority to sign it…', 'busy');

  const record = await api('/api/stamp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hash, parent: state.parent, ...payload }),
  });

  state.parent = '';
  $('parent').hidden = true;
  setStatus('');
  history.replaceState(null, '', `?s=${record.id}`);
  renderCertificate(record, { fresh: true, snapshot });
  resultNode.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function stampFile(file) {
  try {
    setStatus('Fingerprinting your file…', 'busy', 0);
    const hash = await hashBlob(file, (value) => setStatus('Fingerprinting your file…', 'busy', value));
    await createStamp(hash, { kind: 'file', label: $('include-name').checked ? file.name : '' });
  } catch (error) {
    setStatus(error.message, 'error');
  }
}

async function stampSite(address) {
  try {
    setStatus('Fetching the page…', 'busy');

    const page = await api('/api/site', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: address }),
    });
    const snapshot = new Blob([fromBase64(page.body)], { type: page.contentType || 'text/html' });

    setStatus('Fingerprinting the snapshot…', 'busy');
    const hash = await hashBlob(snapshot);
    const { body, ...meta } = page;

    await createStamp(hash, { kind: 'site', meta: { ...meta, url: address } }, snapshot);
  } catch (error) {
    setStatus(error.message, 'error');
  }
}

const drop = $('drop');
const fileInput = $('file-input');

drop.addEventListener('dragover', (event) => {
  event.preventDefault();
  drop.classList.add('is-over');
});
drop.addEventListener('dragleave', () => drop.classList.remove('is-over'));
drop.addEventListener('drop', (event) => {
  event.preventDefault();
  drop.classList.remove('is-over');
  if (event.dataTransfer.files[0]) stampFile(event.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) stampFile(fileInput.files[0]);
  fileInput.value = '';
});

$('panel-site').addEventListener('submit', (event) => {
  event.preventDefault();

  const address = $('site-input').value.trim();
  if (!address) return setStatus('Enter a web address first.', 'error');

  stampSite(/^https?:\/\//i.test(address) ? address : `https://${address}`);
});

document.querySelectorAll('[data-tab]').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('[data-tab]').forEach((item) => item.setAttribute('aria-selected', String(item === tab)));
    $('panel-file').hidden = tab.dataset.tab !== 'file';
    $('panel-site').hidden = tab.dataset.tab !== 'site';
    setStatus('');
  });
});

const linked = new URLSearchParams(location.search).get('s');

if (linked) {
  api(`/api/stamp/${encodeURIComponent(linked)}`)
    .then((record) => renderCertificate(record))
    .catch((error) => setStatus(error.message, 'error'));
}
