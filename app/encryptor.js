const crypto = require('crypto');

// V1 protocol: AES-128-ECB with a generic key (older EWPE/Gree firmware)
const defaultKey = 'a3K8Bx%2r8Y7#xDh';

// V2 protocol: AES-128-GCM with a generic key (newer EWPE/Gree firmware)
const gcmDefaultKey = '{yxAHAY_Lm6pbC/<';
const gcmNonce = Buffer.from('5440784449675a516c5e6313', 'hex');
const gcmAad = Buffer.from('qualcomm-test');

function encrypt(data, key = defaultKey) {
    const cipher = crypto.createCipheriv('aes-128-ecb', key, '');
    const str = cipher.update(JSON.stringify(data), 'utf8', 'base64');
    const request = str + cipher.final('base64');
    return request;
}

function decrypt(data, key = defaultKey) {
    const decipher = crypto.createDecipheriv('aes-128-ecb', key, '');
    const str = decipher.update(data, 'base64', 'utf8');
    const response = JSON.parse(str + decipher.final('utf8'));

    return response;
}

function encryptGcm(data, key = gcmDefaultKey) {
    const cipher = crypto.createCipheriv('aes-128-gcm', key, gcmNonce);
    cipher.setAAD(gcmAad);
    const pack = Buffer.concat([cipher.update(JSON.stringify(data), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return { pack: pack.toString('base64'), tag: tag.toString('base64') };
}

function decryptGcm(data, key = gcmDefaultKey) {
    const decipher = crypto.createDecipheriv('aes-128-gcm', key, gcmNonce);
    decipher.setAAD(gcmAad);
    // Devices don't always return a verifiable auth tag, so decrypt the
    // stream without calling final() and trim anything past the JSON payload.
    const decrypted = decipher.update(Buffer.from(data, 'base64'), undefined, 'utf8');
    const response = JSON.parse(decrypted.slice(0, decrypted.lastIndexOf('}') + 1));

    return response;
}

module.exports = {
    defaultKey,
    gcmDefaultKey,
    encrypt,
    decrypt,
    encryptGcm,
    decryptGcm
}
