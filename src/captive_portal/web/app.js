import { fromB64 } from './crypto/helpers.js';

export function getSignalLevel(rssi) {
    if (Number.isFinite(rssi)) {
        if (rssi >= -67) {
            return 4;
        }
        if (rssi >= -77) {
            return 3;
        }
        if (rssi >= -90) {
            return 2;
        }
        if (rssi >= -110) {
            return 1;
        }
    }
    return 0;
}

export function getSignalLabel(rssi) {
    const level = getSignalLevel(rssi);
    if (level === 4) {
        return 'Excellent signal';
    }
    if (level === 3) {
        return 'Good signal';
    }
    if (level === 2) {
        return 'Fair signal';
    }
    if (level === 1) {
        return 'Weak signal';
    }
    return 'Very weak signal';
}

export function normalizeNetworks(networks = []) {
    return networks
        .filter((network) => (network?.ssid || '').trim().length > 0)
        .map((network) => {
            const parsedRSSI = Number(network?.rssi);
            return {
                ...network,
                ssid: network.ssid.trim(),
                rssi: Number.isFinite(parsedRSSI) ? parsedRSSI : -9999
            };
        })
        .sort((a, b) => b.rssi - a.rssi);
}

export function validateFields({
    wifiSSID,
    wifiPassword,
    rootUserPublicKey,
    repeatRootUserPublicKey,
    hostname,
    setupRootUser,
    setupDeviceHostname
}) {
    const fieldErrors = {
        wifiSSID: '',
        wifiPassword: '',
        rootUserPublicKey: '',
        repeatRootUserPublicKey: '',
        hostname: ''
    };

    if (!wifiSSID || wifiSSID.length > 32) {
        fieldErrors.wifiSSID = 'SSID must be 1 to 32 characters.';
    }

    if (wifiPassword && (wifiPassword.length < 8 || wifiPassword.length > 64)) {
        fieldErrors.wifiPassword = 'Password must be empty or 8 to 64 characters.';
    }

    if (setupRootUser) {
        try {
            const publicKey = new Uint8Array(fromB64(rootUserPublicKey));
            if (publicKey.byteLength !== 65) {
                fieldErrors.rootUserPublicKey = 'Root user key must decode to exactly 65 bytes.';
            }
        } catch (_) {
            fieldErrors.rootUserPublicKey = 'Root user key must be valid Base64 and decode to 65 bytes.';
        }

        if (rootUserPublicKey !== repeatRootUserPublicKey) {
            fieldErrors.repeatRootUserPublicKey = 'Root user key and repeat field must match.';
        }
    }

    if (setupDeviceHostname) {
        if (hostname && !/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(hostname)) {
            fieldErrors.hostname = 'Hostname must be RFC1123 compliant.';
        }
    }

    return fieldErrors;
}

export function hasFieldErrors(fieldErrors) {
    return Object.values(fieldErrors).some(Boolean);
}
