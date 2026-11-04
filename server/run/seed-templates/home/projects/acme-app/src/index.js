require('dotenv').config();
const express = require('express');
const pino = require('pino');
const { pool } = require('./db');
const auth = require('./routes/auth');

const log = pino({ level: process.env.LOG_LEVEL || 'info' });
const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/healthz', async (req, res) => {
  try {
    await pool.query('select 1');
    res.json({ ok: true });
  } catch (err) {
    log.error({ err }, 'db check failed');
    res.status(503).json({ ok: false });
  }
});

app.use('/auth', auth);

const port = Number(process.env.PORT || 3000);
app.listen(port, () => log.info({ port }, 'acme-app listening'));
