import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { DEV_SERVER_PUBLIC_KEY_B64 } from './vite.config.dev-keys.js';
import { decryptEncryptedRequest, readJsonBody } from './vite.config.helpers.js';

// -----------------------------------------------------------------------------

export default defineConfig({
    base: './',
    build: {
        outDir: 'dist',
        assetsDir: 'assets',
        rollupOptions: {
            output: {
                entryFileNames: 'assets/app.js',
                assetFileNames: (assetInfo) => {
                    if (assetInfo.name && assetInfo.name.endsWith('.css')) {
                        return 'assets/app.css';
                    }
                    return 'assets/[name][extname]';
                }
            }
        }
    },
    plugins: [
        svelte(),
        {
            name: 'mock-api',
            configureServer(server) {
                server.middlewares.use('/scan-networks', (req, res, next) => {
                    if (req.method !== 'GET') {
                        return next();
                    }

                    res.setHeader('Content-Type', 'application/json');
                    const networks = [];
                    for (let i = 1; i <= 20; i++) {
                        networks.push({
                            ssid: "Test Wifi " + i.toString(),
                            rssi: -5 - Math.floor(Math.random() * 90),
                            public: Math.random() >= 0.5 ? true : false
                        });
                    }
                    res.end(JSON.stringify({ networks }));
                });

                server.middlewares.use('/init-params', (req, res, next) => {
                    if (req.method !== 'GET') {
                        return next();
                    }

                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({
                        setupRootUser: true,
                        setupDeviceHostname: true
                    }));
                });

                server.middlewares.use('/server-key', (req, res, next) => {
                    if (req.method !== 'GET') {
                        return next();
                    }

                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ publicKey: DEV_SERVER_PUBLIC_KEY_B64 }));
                });

                server.middlewares.use('/provision', async (req, res, next) => {
                    if (req.method !== 'POST') {
                        return next();
                    }

                    try {
                        const body = await readJsonBody(req);
                        const decryptedPayload = await decryptEncryptedRequest(body);
                        console.log('[mock-api] decrypted provisioning payload:', decryptedPayload);

                        res.statusCode = 200;
                        res.setHeader('Content-Type', 'application/json');
                        res.end(JSON.stringify({ ok: true }));
                    } catch (err) {
                        res.statusCode = 400;
                        res.setHeader('Content-Type', 'text/plain');
                        res.end(`Provisioning decrypt failed: ${err instanceof Error ? err.message : 'unknown error'}`);
                    }
                });
            }
        }
    ],
    server: {
        port: 3000,
        open: true,
        host: true
    }
});
