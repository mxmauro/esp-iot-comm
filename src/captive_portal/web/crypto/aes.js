import { gcm } from '@noble/ciphers/aes.js';

import { toArrayBuffer, toArrayBufferView } from './helpers.js';

// -----------------------------------------------------------------------------

export const createAesCrypto = () => {
    return new AesCrypto();
};

// -----------------------------------------------------------------------------

class AesCrypto {
    constructor() {
        this.key = undefined;
    }

    async setKey(key) {
        this.key = new Uint8Array(toArrayBufferView(key));
    }

    async encrypt(plaintext, iv, aad) {
        if (!this.key) {
            throw new Error('Crypto key not set');
        }

        const encrypted = gcm(
            this.key,
            new Uint8Array(toArrayBufferView(iv)),
            aad ? new Uint8Array(toArrayBufferView(aad)) : undefined
        ).encrypt(
            new Uint8Array(toArrayBufferView(plaintext))
        );

        return toArrayBuffer(encrypted);
    }

    async decrypt(ciphertext, iv, aad) {
        if (!this.key) {
            throw new Error('Crypto key not set');
        }

        const decrypted = gcm(
            this.key,
            new Uint8Array(toArrayBufferView(iv)),
            aad ? new Uint8Array(toArrayBufferView(aad)) : undefined
        ).decrypt(
            new Uint8Array(toArrayBufferView(ciphertext))
        );

        return toArrayBuffer(decrypted);
    }
}
