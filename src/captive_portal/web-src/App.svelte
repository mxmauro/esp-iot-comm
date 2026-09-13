<script>
import { onMount } from 'svelte';
import { getSignalLevel, getSignalLabel } from './app.js';
import { hasFieldErrors, validateFields } from './app.js';
import { normalizeNetworks } from './app.js';
import { createAesCrypto } from './crypto/aes.js';
import { createECDHCrypto } from './crypto/ecp.js';
import { fromB64, toB64 } from './crypto/helpers.js';
import { createHkdfCrypto } from './crypto/hkdf.js';
import { randomize } from './crypto/random.js';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';

// -----------------------------------------------------------------------------

const textEncoder = new TextEncoder();
const HKDF_INFO = textEncoder.encode('iot-comm/provisioning/v1');
const RECOVERY_AUTH_DOMAIN = textEncoder.encode('iot-comm/captive-portal-recovery/v1');

// -----------------------------------------------------------------------------

let networks = [];
let wifiSSID = '';
let wifiPassword = '';
let rootUserPublicKey = '';
let repeatRootUserPublicKey = '';
let hostname = '';

let error = '';
let fieldErrors = {
    wifiSSID: '',
    wifiPassword: '',
    rootUserPublicKey: '',
    repeatRootUserPublicKey: '',
    hostname: ''
};

let submitting = false;
let scanningNetworks = false;
let provisioned = false;
let showNetworkModal = false;
let showPassword = false;
let loadingInitParams = true;
let initParamsError = '';
let setupRootUser = true;
let setupDeviceHostname = true;
let requestWifiCredentials = true;
let requireRootAuthorization = false;
let rootAuthorizationChallenge = '';
let rootUserPrivateKey = '';

// -----------------------------------------------------------------------------

function selectNetwork(ssid) {
    wifiSSID = ssid;
    fieldErrors = { ...fieldErrors, wifiSSID: '' };
    showNetworkModal = false;
}

function clearFieldError(fieldName) {
    if (!fieldErrors[fieldName]) {
        return;
    }
    fieldErrors = { ...fieldErrors, [fieldName]: '' };
}

async function loadInitParams() {
    initParamsError = '';
    loadingInitParams = true;

    try {
        const response = await fetch('/init-params');
        if (!response.ok) {
            throw new Error('Unable to fetch init params');
        }

        const body = await response.json();
        requestWifiCredentials = body?.requestWifiCredentials === true;
        setupRootUser = body?.setupRootUser !== false;
        setupDeviceHostname = body?.setupDeviceHostname !== false;
        requireRootAuthorization = body?.requireRootAuthorization === true;
        rootAuthorizationChallenge = body?.rootAuthorizationChallenge || '';
        if (requireRootAuthorization && !rootAuthorizationChallenge) {
            throw new Error('Missing recovery authorization challenge');
        }

        if (!setupRootUser) {
            rootUserPublicKey = '';
            repeatRootUserPublicKey = '';
            fieldErrors = {
                ...fieldErrors,
                rootUserPublicKey: '',
                repeatRootUserPublicKey: ''
            };
        }

        if (!setupDeviceHostname) {
            hostname = '';
            fieldErrors = {
                ...fieldErrors,
                hostname: ''
            };
        }
    } catch (_) {
        initParamsError = 'Unable to load provisioning options.';
    } finally {
        loadingInitParams = false;
    }
}

function createRecoveryAuthorization() {
    try {
        const privateKey = new Uint8Array(fromB64(rootUserPrivateKey));
        const challenge = new Uint8Array(fromB64(rootAuthorizationChallenge));
        const ssid = textEncoder.encode(wifiSSID);
        const password = textEncoder.encode(wifiPassword);

        if (privateKey.byteLength !== 32 || challenge.byteLength !== 32 || ssid.byteLength > 32 || password.byteLength > 64) {
            throw new Error('Invalid recovery authorization data');
        }

        const transcript = new Uint8Array(RECOVERY_AUTH_DOMAIN.length + challenge.length + 2 + ssid.length + password.length);
        let offset = 0;
        transcript.set(RECOVERY_AUTH_DOMAIN, offset);
        offset += RECOVERY_AUTH_DOMAIN.length;
        transcript.set(challenge, offset);
        offset += challenge.length;
        transcript[offset++] = ssid.length;
        transcript.set(ssid, offset);
        offset += ssid.length;
        transcript[offset++] = password.length;
        transcript.set(password, offset);
        return toB64(p256.sign(sha256(transcript), privateKey, { prehash: false, format: 'compact' }));
    } finally {
        rootUserPrivateKey = '';
    }
}

async function getServerPublicKey() {
    const response = await fetch('/server-key');
    if (!response.ok) {
        throw new Error('Unable to fetch server public key');
    }

    const body = await response.json();
    if (!body?.publicKey) {
        throw new Error('Invalid server key response');
    }

    return fromB64(body.publicKey);
}

async function scanNetworks() {
    error = '';
    scanningNetworks = true;

    try {
        const response = await fetch('/scan-networks');
        if (!response.ok) {
            throw new Error('scan-networks failed');
        }
        const data = await response.json();
        networks = normalizeNetworks(data.networks || []);
        showNetworkModal = true;
    } catch (_) {
        error = 'Unable to scan Wi-Fi networks.';
    } finally {
        scanningNetworks = false;
    }
}

async function submitProvisioning() {
    error = '';
    wifiSSID = wifiSSID.trim();
    rootUserPublicKey = rootUserPublicKey.trim();
    repeatRootUserPublicKey = repeatRootUserPublicKey.trim();
    hostname = hostname.trim();

    fieldErrors = validateFields({
        wifiSSID,
        wifiPassword,
        rootUserPublicKey,
        repeatRootUserPublicKey,
        hostname,
        setupRootUser,
        setupDeviceHostname,
        requestWifiCredentials
    });

    if (hasFieldErrors(fieldErrors)) {
        return;
    }
    if (requireRootAuthorization && !rootUserPrivateKey) {
        error = 'Root user private key is required to authorize recovery.';
        return;
    }

    submitting = true;

    try {
        const serverPublicKey = await getServerPublicKey();

        const ecdh = createECDHCrypto();
        await ecdh.generateKeys();
        const clientPublicKey = await ecdh.saveRawPublicKey();
        await ecdh.loadRawPublicKey(serverPublicKey);
        const sharedSecret = await ecdh.computeSharedSecret();

        const nonce = randomize(12);
        const iv = randomize(12);
        const hkdf = createHkdfCrypto();
        const encryptionKey = await hkdf.deriveKey(sharedSecret, nonce, HKDF_INFO, 32);

        const aes = createAesCrypto();
        await aes.setKey(encryptionKey);

        const provisioningData = {};

        if (requestWifiCredentials) {
            provisioningData.wifiSSID = wifiSSID;
            provisioningData.wifiPassword = wifiPassword;
        }

        if (requireRootAuthorization) {
            provisioningData.rootAuthorization = createRecoveryAuthorization();
        }

        if (setupRootUser) {
            provisioningData.rootUserPublicKey = rootUserPublicKey;
        }

        if (setupDeviceHostname) {
            provisioningData.hostname = hostname;
        }

        const plaintext = textEncoder.encode(JSON.stringify(provisioningData));

        const encryptedPayload = await aes.encrypt(plaintext, iv);

        const response = await fetch('/provision', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                clientPublicKey: toB64(clientPublicKey),
                nonce: toB64(nonce),
                iv: toB64(iv),
                encryptedPayload: toB64(encryptedPayload)
            })
        });

        if (response.ok) {
            provisioned = true;
            showNetworkModal = false;
        } else {
            error = await response.text();
        }
    } catch (err) {
        // error = err.toString ? err.toString() : (err.message || 'Failed to submit provisioning data. Please try again.');
        error = 'Failed to submit provisioning data. Please try again.';
    } finally {
        submitting = false;
    }
}

onMount(() => {
    loadInitParams();
});
</script>

<main>
{#if provisioned}
    <section class="success-card" role="status" aria-live="polite">
        <div class="status-icon-wrap success-icon-wrap" aria-hidden="true">
            <svg class="status-icon success-icon" viewBox="0 0 48 48" fill="none">
                <circle cx="24" cy="24" r="22" />
                <path d="M14 24.8L21.2 32L34.2 18.8" />
            </svg>
        </div>
        <h2>Provisioning Complete</h2>
        <p class="success-text">Provisioning data saved. Device will continue setup.</p>
    </section>
{:else if !loadingInitParams && initParamsError}
    <section class="success-card error-card" role="alert" aria-live="assertive">
        <div class="status-icon-wrap error-icon-wrap" aria-hidden="true">
            <svg class="status-icon error-icon" viewBox="0 0 48 48" fill="none">
                <circle cx="24" cy="24" r="22" />
                <path d="M24 15.5V25.5" />
                <path d="M24 32.5h.01" />
            </svg>
        </div>
        <h2>Unable to Load Configuration</h2>
        <p class="success-text error-text">{initParamsError}</p>
        <button type="button" class="submit" on:click={loadInitParams}>Retry</button>
    </section>
{:else}
    <section class="card">
        <h1>{requireRootAuthorization ? 'Wi-Fi Recovery' : 'Device Wi-Fi Provisioning'}</h1>
        <p class="subtitle">{requireRootAuthorization ? 'Authorize replacement Wi-Fi credentials with the existing root private key.' : 'Connect your device to Wi-Fi and configure device parameters.'}</p>

    {#if loadingInitParams}
        <p class="loading-state">Loading configuration...</p>
    {:else}
        <form novalidate autocomplete="off" on:submit|preventDefault>
            <input class="autofill-decoy" type="text" name="username" autocomplete="username" tabindex="-1" aria-hidden="true" />
            <input class="autofill-decoy" type="password" name="password" autocomplete="current-password" tabindex="-1" aria-hidden="true" />

        {#if requestWifiCredentials}
            <label class="ssid-field">
            Wi-Fi SSID
            <div class="ssid-input-wrap">
                <input
                    class="ssid-input"
                    class:error-input={fieldErrors.wifiSSID}
                    bind:value={wifiSSID}
                    on:input={() => clearFieldError('wifiSSID')}
                    name="wifi-network-ssid"
                    maxlength="32"
                    autocomplete="off"
                    autocapitalize="off"
                    autocorrect="off"
                    spellcheck="false"
                    data-lpignore="true"
                    data-1p-ignore="true"
                    data-form-type="other"
                    placeholder="Select or type SSID (hidden network)"
                    disabled={submitting}
                />
                <button
                    type="button"
                    class="scan-inline"
                    on:click={scanNetworks}
                    disabled={submitting || scanningNetworks}
                >
                    {scanningNetworks ? 'Scanning...' : 'Scan'}
                </button>
            </div>
        {#if fieldErrors.wifiSSID}
            <small class="field-error">{fieldErrors.wifiSSID}</small>
        {/if}
            </label>
        {/if}

        {#if requestWifiCredentials}
            <label>
                Wi-Fi password:
                <div class="password-input-wrap">
                    <input
                        type={showPassword ? 'text' : 'password'}
                        class:error-input={fieldErrors.wifiPassword}
                        class="password-input"
                        bind:value={wifiPassword}
                        on:input={() => clearFieldError('wifiPassword')}
                        maxlength="64"
                        name="wifi-passphrase"
                        autocomplete="off"
                        autocapitalize="off"
                        autocorrect="off"
                        spellcheck="false"
                        data-lpignore="true"
                        data-1p-ignore="true"
                        data-form-type="other"
                        placeholder="Leave empty for open networks"
                        disabled={submitting}
                    />
                    <button
                        type="button"
                        class="password-toggle"
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        aria-pressed={showPassword}
                        on:click={() => (showPassword = !showPassword)}
                        disabled={submitting}
                    >
                        <svg viewBox="0 0 24 24" aria-hidden="true">
                            <path d="M1.5 12s3.8-6.5 10.5-6.5S22.5 12 22.5 12s-3.8 6.5-10.5 6.5S1.5 12 1.5 12Z" />
                            <circle cx="12" cy="12" r="3.25" />
                            {#if !showPassword}
                                <path d="M4 20 20 4" />
                            {/if}
                        </svg>
                    </button>
                </div>
        {#if fieldErrors.wifiPassword}
                <small class="field-error">{fieldErrors.wifiPassword}</small>
        {/if}
            </label>
        {/if}

        {#if requireRootAuthorization}
            <label>
                Root user private key:
                <input
                    type="password"
                    bind:value={rootUserPrivateKey}
                    maxlength="44"
                    autocomplete="off"
                    autocapitalize="off"
                    autocorrect="off"
                    spellcheck="false"
                    placeholder="Base64 raw 32-byte private key"
                    disabled={submitting}
                />
                <small>Used only to authorize this recovery request; it is cleared before transmission.</small>
            </label>
        {/if}

        {#if setupRootUser}
            <label>
                Root user public key:
                <input
                    class:error-input={fieldErrors.rootUserPublicKey}
                    bind:value={rootUserPublicKey}
                    on:input={() => {
                        clearFieldError('rootUserPublicKey');
                        clearFieldError('repeatRootUserPublicKey');
                    }}
                    name="root-user-public-key"
                    autocomplete="off"
                    autocapitalize="off"
                    autocorrect="off"
                    spellcheck="false"
                    data-lpignore="true"
                    data-1p-ignore="true"
                    data-form-type="other"
                    maxlength="88"
                    disabled={submitting}
                />
            {#if fieldErrors.rootUserPublicKey}
                <small class="field-error">{fieldErrors.rootUserPublicKey}</small>
            {/if}
            </label>

            <label>
                Repeat root user public key:
                <input
                    class:error-input={fieldErrors.repeatRootUserPublicKey}
                    bind:value={repeatRootUserPublicKey}
                    on:input={() => clearFieldError('repeatRootUserPublicKey')}
                    name="repeat-root-user-public-key"
                    autocomplete="off"
                    autocapitalize="off"
                    autocorrect="off"
                    spellcheck="false"
                    data-lpignore="true"
                    data-1p-ignore="true"
                    data-form-type="other"
                    maxlength="88"
                    disabled={submitting}
                />
            {#if fieldErrors.repeatRootUserPublicKey}
                <small class="field-error">{fieldErrors.repeatRootUserPublicKey}</small>
            {/if}
            </label>
        {/if}

        {#if setupDeviceHostname}
            <label>
                Device custom hostname:
                <input
                    class:error-input={fieldErrors.hostname}
                    bind:value={hostname}
                    on:input={() => clearFieldError('hostname')}
                    maxlength="63"
                    autocomplete="off"
                    autocapitalize="off"
                    autocorrect="off"
                    spellcheck="false"
                    placeholder="e.g.: my-device"
                    disabled={submitting}
                />
            {#if fieldErrors.hostname}
                <small class="field-error">{fieldErrors.hostname}</small>
            {/if}
            </label>
        {/if}

            <button
                type="button"
                class="submit"
                on:click={submitProvisioning}
                disabled={submitting}
            >
                {submitting ? 'Saving...' : requireRootAuthorization ? 'Authorize & Recover' : 'Save & Provision'}
            </button>

        {#if error}
            <p class="error">Error: {error}</p>
        {/if}
        </form>
    {/if}
    </section>
{/if}

{#if showNetworkModal}
    <div
        class="modal-backdrop"
        role="button"
        tabindex="0"
        aria-label="Close network picker"
        on:click={(event) => {
            if (event.target === event.currentTarget) {
                showNetworkModal = false;
            }
        }}
        on:keydown={(event) => event.key === 'Escape' && (showNetworkModal = false)}
    >
        <div class="modal" role="dialog" aria-modal="true" aria-label="Choose Wi-Fi network" tabindex="-1">
            <div class="modal-header">
                <h2>Select Wi-Fi Network</h2>
                <button type="button" class="close-modal" on:click={() => (showNetworkModal = false)}>Close</button>
            </div>

    {#if networks.length === 0}
            <p class="modal-empty">No visible networks found. Enter the SSID manually.</p>
    {:else}
            <div class="network-list">
        {#each networks as network}
                <button
                    type="button"
                    class="network-item"
                    on:click={() => selectNetwork(network.ssid)}
                >
                    <span class="network-name">{network.ssid}</span>
                    <span class="network-rssi" aria-label={getSignalLabel(network.rssi)} title={`${network.rssi} dBm`}>
                        <span class="signal-bars" aria-hidden="true">
            {#each [0, 1, 2, 3] as bar}
                            <span class:active={bar < getSignalLevel(network.rssi)}></span>
            {/each}
                        </span>
                    </span>
                </button>
        {/each}
            </div>
    {/if}
        </div>
    </div>
{/if}
</main>
