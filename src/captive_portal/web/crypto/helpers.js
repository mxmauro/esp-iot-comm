function isNodeBuffer(input) {
    return typeof Buffer !== 'undefined' && Buffer.isBuffer(input);
}

function toUint8Array(input, varName) {
    if (input instanceof Uint8Array) {
        return new Uint8Array(input);
    }
    if (input instanceof ArrayBuffer) {
        return new Uint8Array(input);
    }
    if (isNodeBuffer(input)) {
        return new Uint8Array(input);
    }
    if (input instanceof DataView) {
        return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    }
    if (ArrayBuffer.isView(input)) {
        return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    }

    if (varName) {
        throw new TypeError(`${varName} is an unsupported input type`);
    }
    throw new TypeError('Unsupported input type');
}

export function toDataView(data, varName) {
    if (Array.isArray(data)) {
        return new DataView(toArrayBuffer(data));
    }
    if (data instanceof DataView) {
        return data;
    }

    const view = toUint8Array(data, varName);
    return new DataView(view.buffer, view.byteOffset, view.byteLength);
}

export function toArrayBufferView(src) {
    if (Array.isArray(src)) {
        return new Uint8Array(toArrayBuffer(src));
    }
    return toUint8Array(src);
}

export function toArrayBuffer(src) {
    const parts = Array.isArray(src) ? src : [src];
    const views = parts.map((part) => toUint8Array(part));
    const totalLength = views.reduce((sum, view) => sum + view.byteLength, 0);
    const output = new Uint8Array(totalLength);

    let offset = 0;
    for (const view of views) {
        output.set(view, offset);
        offset += view.byteLength;
    }

    return output.buffer;
}

export function stringToNulTerminatedBuffer(value) {
    const encoder = new TextEncoder();
    const payload = encoder.encode(String(value));
    const output = new Uint8Array(payload.length + 1);
    output.set(payload);
    output[output.length - 1] = 0;
    return output;
}

export function fromB64(value, urlSafe = false) {
    let normalized = value;
    if (urlSafe) {
        normalized = normalized.replace(/-/g, '+').replace(/_/g, '/');
        while (normalized.length % 4 !== 0) {
            normalized += '=';
        }
    }

    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

export function toB64(data) {
    let bytes;
    if (data instanceof ArrayBuffer) {
        bytes = new Uint8Array(data);
    } else if (ArrayBuffer.isView(data)) {
        bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else {
        throw new TypeError('Unsupported input type');
    }

    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
