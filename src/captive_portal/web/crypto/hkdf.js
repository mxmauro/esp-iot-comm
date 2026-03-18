import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { toArrayBuffer, toArrayBufferView } from './helpers.js';

// -----------------------------------------------------------------------------

export const createHkdfCrypto = () => {
    return new HkdfCrypto();
};

// -----------------------------------------------------------------------------

class HkdfCrypto {
    async deriveKey(key, salt, info, keyLen) {
        const derivedBits = hkdf(
            sha256,
            new Uint8Array(toArrayBufferView(key)),
            new Uint8Array(toArrayBufferView(salt)),
            new Uint8Array(toArrayBufferView(info)),
            keyLen
        );

        return toArrayBuffer(derivedBits);
    }
}
