const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json({ verify: rawBodySaver }));

const issuedRefs = new Set();

function rawBodySaver(req, res, buf) {
  req.rawBody = buf.toString();
}

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET;
const CHIMONEY_API_KEY = process.env.CHIMONEY_API_KEY;

app.post('/secure-webhook', async (req, res) => {
  const signature = req.headers['x-paystack-signature'];
  const hash = crypto
    .createHmac('sha512', PAYSTACK_SECRET)
    .update(req.rawBody)
    .digest('hex');

  if (signature !== hash) {
    return res.status(401).send('Invalid signature');
  }

  const { email, amount, reference } = req.body.data;

  if (issuedRefs.has(reference)) {
    return res.status(409).send('Duplicate transaction');
  }
  issuedRefs.add(reference);

  try {
    const response = await axios.post(
      'https://api.chimoney.io/v0.2/payouts/chi/send',
      {
        email,
        valueInUSD: amount / 100,
        wallet: true
      },
      {
        headers: {
          'X-API-KEY': CHIMONEY_API_KEY,
          'Content-Type': 'application/json'
        }
      }
    );

    res.status(200).json({ status: 'Secure Chi sent', data: response.data });
  } catch (err) {
    console.error('Chi Secure Error:', err.response?.data || err.message);
    res.status(500).send('Chi payout failed');
  }
});

app.listen(3001, () => console.log('🟢 Secure server running on port 3001'));
