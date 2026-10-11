import crypto from 'node:crypto';
const { SUPABASE_URL: U, SUPABASE_SERVICE_KEY: K, JWT_SECRET: S, ADMIN_PASSWORD: AP } = process.env;
const BUCKET = 'uploads';
const H = { apikey: K, Authorization: 'Bearer ' + K };

async function sb(path, { method = 'GET', body } = {}) {
  const r = await fetch(U + '/rest/v1/' + path, {
    method, headers: { ...H, 'Content-Type': 'application/json', Prefer: 'return=representation' },
    body: body ? JSON.stringify(body) : undefined
  });
  const t = await r.text();
  if (!r.ok) throw new Error(t);
  return t ? JSON.parse(t) : [];
}
const mac = d => crypto.createHmac('sha256', S).update(d).digest('base64url');
const sign = p => { const d = Buffer.from(JSON.stringify(p)).toString('base64url'); return d + '.' + mac(d); };
function verify(t) {
  if (!t || !t.includes('.')) return null;
  const [d, s] = t.split('.'); const e = mac(d);
  if (e.length !== s.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(s))) return null;
  try { const p = JSON.parse(Buffer.from(d, 'base64url')); return p.exp > Date.now() ? p : null; } catch { return null; }
}
const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
const check = (pw, h) => { const x = hash(pw, h.split(':')[0]); return x.length === h.length && crypto.timingSafeEqual(Buffer.from(x), Buffer.from(h)); };
const q = encodeURIComponent;

export default async function handler(req, res) {
  const out = (c, o) => res.status(c).json(o);
  try {
    if (!U || !K || !S || !AP) return out(500, { error: 'Server env variables set nahi hain' });
    const a = req.query.a, b = req.body || {};
    const p = verify((req.headers.authorization || '').replace('Bearer ', ''));
    let me = null;
    if (p) {
      if (p.role === 'admin') me = { id: 'admin', name: 'Admin', role: 'admin', status: 'approved' };
      else { const r = await sb(`users?id=eq.${q(p.id)}&select=id,name,number,status`); if (r[0]) me = { ...r[0], role: 'student' }; }
    }
    const ok = me && me.status === 'approved', adm = me && me.role === 'admin';

    if (a === 'public') {
      const subjects = await sb('subjects?select=*&order=name');
      const units = await sb('units?select=*&order=created_at');
      const uploads = await sb('uploads?select=id,subject_id,unit_id,type,title,user_id,user_name,content_type,created_at&order=created_at.desc');
      return out(200, { subjects, units, uploads, me });
    }
    if (a === 'register') {
      const name = String(b.name || '').trim(), number = String(b.number || '').trim(), pw = String(b.password || '');
      if (name.length < 2 || name.length > 60 || number.length < 3 || number.length > 20 || pw.length < 4) return out(400, { error: 'Name, number aur password (min 4) sahi se bharo' });
      if (number.toLowerCase() === 'admin') return out(400, { error: 'Ye number allowed nahi hai' });
      try { await sb('users', { method: 'POST', body: { name, number, pass_hash: hash(pw) } }); }
      catch (e) { return out(409, { error: 'Is number se request pehle se hai' }); }
      return out(200, { ok: true });
    }
    if (a === 'login') {
      const number = String(b.number || '').trim(), pw = String(b.password || '');
      const exp = Date.now() + 30 * 864e5;
      if (number.toLowerCase() === 'admin') {
        const x = Buffer.from(pw), y = Buffer.from(AP);
        if (x.length !== y.length || !crypto.timingSafeEqual(x, y)) return out(401, { error: 'Galat admin password' });
        return out(200, { token: sign({ role: 'admin', exp }) });
      }
      const r = await sb(`users?number=eq.${q(number)}&select=*`);
      if (!r[0] || !check(pw, r[0].pass_hash)) return out(401, { error: 'Number ya password galat hai' });
      if (r[0].status === 'rejected') return out(403, { error: 'Aapki request reject ho chuki hai' });
      return out(200, { token: sign({ id: r[0].id, exp }) });
    }
    if (!me) return out(401, { error: 'Login karo' });

    if (a === 'users' && adm) return out(200, await sb('users?select=id,name,number,status,created_at&order=created_at.desc'));
    if (a === 'setstatus' && adm) {
      if (!['pending', 'approved', 'rejected', 'banned'].includes(b.status)) return out(400, { error: 'bad status' });
      await sb(`users?id=eq.${q(b.id)}`, { method: 'PATCH', body: { status: b.status } }); return out(200, { ok: true });
    }
    if (a === 'subject' && adm) {
      const name = String(b.name || '').trim(); if (!name) return out(400, { error: 'Naam likho' });
      try { await sb('subjects', { method: 'POST', body: { name } }); } catch { return out(409, { error: 'Subject pehle se hai' }); }
      return out(200, { ok: true });
    }
    if (a === 'unit' && adm) {
      const name = String(b.name || '').trim(); if (!name || !b.subject_id) return out(400, { error: 'Unit ka naam likho' });
      await sb('units', { method: 'POST', body: { subject_id: b.subject_id, name } }); return out(200, { ok: true });
    }
    if (a === 'delunit' && adm) { await sb(`units?id=eq.${q(b.id)}`, { method: 'DELETE' }); return out(200, { ok: true }); }
    if (a === 'delsubject' && adm) { await sb(`subjects?id=eq.${q(b.id)}`, { method: 'DELETE' }); return out(200, { ok: true }); }

    const canView = me.status === 'approved' || me.status === 'banned';
    if (!canView) return out(403, { error: 'Admin approval pending hai' });

    if (a === 'signupload' || a === 'addupload') {
      if (!ok) return out(403, { error: me.status === 'banned' ? 'Admin ne aapko upload se ban kiya hai' : 'Admin approval pending hai' });
    }
    if (a === 'signupload') {
      const fn = String(b.filename || 'file').replace(/[^\w.\-]/g, '_').slice(-80);
      const path = `${me.id}/${Date.now()}-${fn}`;
      const r = await fetch(`${U}/storage/v1/object/upload/sign/${BUCKET}/${path}`, { method: 'POST', headers: H });
      const j = await r.json(); if (!r.ok) return out(500, { error: j.message || 'Storage error' });
      return out(200, { path, url: U + '/storage/v1' + j.url });
    }
    if (a === 'addupload') {
      if (!String(b.path || '').startsWith(me.id + '/')) return out(400, { error: 'bad path' });
      const un = (await sb(`units?id=eq.${q(b.unit_id)}&select=subject_id`))[0];
      if (!un || un.subject_id !== b.subject_id) return out(400, { error: 'Unit sahi nahi hai' });
      const type = ['Assignment', 'Experiment', 'Other'].includes(b.type) ? b.type : 'Other';
      await sb('uploads', { method: 'POST', body: { subject_id: b.subject_id, unit_id: b.unit_id, type, title: String(b.title || '').slice(0, 120), path: b.path, content_type: b.content_type || '', user_id: adm ? null : me.id, user_name: me.name } });
      return out(200, { ok: true });
    }
    if (a === 'file') {
      const r = (await sb(`uploads?id=eq.${q(req.query.id)}&select=path`))[0]; if (!r) return out(404, { error: 'Nahi mila' });
      const s = await fetch(`${U}/storage/v1/object/sign/${BUCKET}/${r.path}`, { method: 'POST', headers: { ...H, 'Content-Type': 'application/json' }, body: JSON.stringify({ expiresIn: 3600 }) });
      const j = await s.json(); if (!s.ok) return out(500, { error: 'Sign fail' });
      return out(200, { url: U + '/storage/v1' + j.signedURL });
    }
    if (a === 'delupload') {
      const r = (await sb(`uploads?id=eq.${q(b.id)}&select=path,user_id`))[0]; if (!r) return out(404, { error: 'Nahi mila' });
      if (!adm && r.user_id !== me.id) return out(403, { error: 'Sirf apna upload delete kar sakte ho' });
      await fetch(`${U}/storage/v1/object/${BUCKET}/${r.path}`, { method: 'DELETE', headers: H });
      await sb(`uploads?id=eq.${q(b.id)}`, { method: 'DELETE' }); return out(200, { ok: true });
    }
    return out(404, { error: 'Unknown action' });
  } catch (e) { return out(500, { error: 'Server error' }); }
}
