import { p256 } from '@noble/curves/nist.js';
import { toArrayBuffer, toArrayBufferView, toDataView } from './helpers.js';

// -----------------------------------------------------------------------------

export const createECDHCrypto = () => {
    return new EcpCrypto();
};

// -----------------------------------------------------------------------------

class EcpCrypto {
    constructor() {
        this.privKey = undefined;
        this.pubKey = undefined;
    }

    async generateKeys() {
        this.privKey = p256.utils.randomSecretKey();
        this.pubKey = p256.getPublicKey(this.privKey, false);
    }

    async loadRawPublicKey(pubKey) {
        if (pubKey.byteLength !== 65) {
            throw new Error('Public key size must be 65 bytes');
        }
        const pubKeyView = toDataView(pubKey);
        if (pubKeyView.getUint8(0) !== 0x04) {
            throw new Error('Public key must be in uncompressed format (0x04 + x + y)');
        }

        this.pubKey = new Uint8Array(toArrayBufferView(pubKey));
    }

    async loadRawPrivateKey(privKey) {
        if (privKey.byteLength !== 32) {
            throw new Error('Private key size must be 32 bytes');
        }

        this.privKey = new Uint8Array(toArrayBufferView(privKey));
    }

    async saveRawPublicKey() {
        if (!this.pubKey) {
            throw new Error('ECP public key not available.');
        }

        return toArrayBuffer(this.pubKey);
    }

    async saveRawPrivateKey() {
        if (!this.privKey) {
            throw new Error('ECP private key not available.');
        }

        if (this.privKey.byteLength !== 32) {
            throw new Error('Unexpected private key length.');
        }

        return toArrayBuffer(this.privKey);
    }

    createPkcs8PrivateKey(privKey) {
        if (privKey.byteLength !== 32) {
            throw new Error('Private key size must be 32 bytes');
        }

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
        return toArrayBuffer([pkcs8Prefix, privKey, pkcs8Suffix]);
    }

    async computeSharedSecret() {
        if (!(this.privKey && this.pubKey)) {
            throw new Error('ECP private and public keys are not available.');
        }

        const sharedPoint = p256.getSharedSecret(this.privKey, this.pubKey, false);
        return toArrayBuffer(sharedPoint.subarray(1, 33));
    }
}
