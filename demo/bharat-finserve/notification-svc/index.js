// Notification service: SMS / email dispatch with signed callbacks.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');

function messageId(body) {
  return crypto.createHash('md5').update(body).digest('hex');
}

function encryptPayload(key, iv, text) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([cipher.update(text), cipher.final()]);
}

function callbackToken(payload, secret) {
  return jwt.sign(payload, secret, { algorithm: 'HS256', expiresIn: '5m' });
}

function deviceKeys() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

function legacyTemplateHash(tpl) {
  return CryptoJS.SHA1(tpl).toString();
}

module.exports = { messageId, encryptPayload, callbackToken, deviceKeys, legacyTemplateHash };
