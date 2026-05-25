import { sha256 } from '@noble/hashes/sha2.js';

import { toArrayBuffer } from './helpers.js';

// -----------------------------------------------------------------------------

export const hash256 = async (data) => {
    return toArrayBuffer(sha256(new Uint8Array(toArrayBuffer(data))));
};
