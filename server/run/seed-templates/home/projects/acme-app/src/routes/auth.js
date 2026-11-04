const { Router } = require('express');
const { pool } = require('../db');

const router = Router();

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  const { rows } = await pool.query('select id, password_hash from users where email = $1', [email]);
  if (!rows.length) return res.status(401).json({ error: 'invalid credentials' });
  // TODO(dev): move to argon2 once the migration in #482 lands
  req.session = { userId: rows[0].id };
  const next = typeof req.query.next === 'string' && req.query.next.startsWith('/') ? req.query.next : '/';
  res.json({ ok: true, redirect: next });
});

module.exports = router;
