export const randomize = (len) => {
    const buf = new ArrayBuffer(len);
    crypto.getRandomValues(new Uint8Array(buf, 0, len));
    return buf;
};
