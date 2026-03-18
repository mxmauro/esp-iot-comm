import { webcrypto } from 'node:crypto';
import { DEV_SERVER_PRIVATE_KEY_B64, HKDF_INFO } from './vite.config.dev-keys.js';

// -----------------------------------------------------------------------------

const subtle = webcrypto.subtle;
const textDecoder = new TextDecoder();

// -----------------------------------------------------------------------------

const toBytes = (b64) => Uint8Array.from(Buffer.from(b64, 'base64'));
const toArrayBuffer = (bytes) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);

// -----------------------------------------------------------------------------

export const readJsonBody = async (req) => {
    const chunks = [];
    for await (const chunk of req) {
        chunks.push(Buffer.from(chunk));
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
};

export const decryptEncryptedRequest = async (body) => {
    const clientPublicKeyRaw = toBytes(body.clientPublicKey);
    const nonce = toBytes(body.nonce);
    const iv = toBytes(body.iv);
    const encryptedPayload = toBytes(body.encryptedPayload);
    const serverPrivateKeyRaw = toBytes(DEV_SERVER_PRIVATE_KEY_B64);

    const serverPrivateKey = await subtle.importKey(
        'pkcs8',
        createPkcs8PrivateKey(serverPrivateKeyRaw),
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits']
    );

    const clientPublicKey = await subtle.importKey(
        'raw',
        toArrayBuffer(clientPublicKeyRaw),
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    );

    const sharedSecret = await subtle.deriveBits(
        {
            name: 'ECDH',
            public: clientPublicKey
        },
        serverPrivateKey,
        256
    );

    const hkdfBaseKey = await subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
    const aesKeyRaw = await subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: toArrayBuffer(nonce),
            info: HKDF_INFO
        },
        hkdfBaseKey,
        256
    );

    const encryptionKey = await subtle.importKey('raw', aesKeyRaw, { name: 'AES-GCM' }, false, ['decrypt']);
    const decrypted = await subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: toArrayBuffer(iv),
            tagLength: 128
        },
        encryptionKey,
        toArrayBuffer(encryptedPayload)
    );

    return JSON.parse(textDecoder.decode(decrypted));
};

// -----------------------------------------------------------------------------

const createPkcs8PrivateKey = (privKeyBytes) => {
    const pkcs8Prefix = Uint8Array.from([
        0x30, 0x4d,
        0x02, 0x01, 0x00,
        0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x04, 0x33,
        0x30, 0x31,
        0x02, 0x01, 0x01,
        0x04, 0x20
    ]);
    const pkcs8Suffix = Uint8Array.from([
        0xa0, 0x0a,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    ]);

    const merged = new Uint8Array(pkcs8Prefix.length + privKeyBytes.length + pkcs8Suffix.length);
    merged.set(pkcs8Prefix, 0);
    merged.set(privKeyBytes, pkcs8Prefix.length);
    merged.set(pkcs8Suffix, pkcs8Prefix.length + privKeyBytes.length);
    return toArrayBuffer(merged);
};
