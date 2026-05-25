---
name: esp-iot-comm-web-ui
description: Work on the captive portal frontend for esp-iot-comm. Use when Codex is changing Svelte or Vite files under `src/captive_portal/web-src/`, updating onboarding UI behavior, changing mocked dev-server API behavior, or regenerating the embedded assets consumed from `src/captive_portal/web-dist/`.
---

# Esp Iot Comm Web Ui

Use this skill only for the captive portal frontend and its generated assets. The backend HTTP handlers that serve the embedded files stay in C++, but the editable UI source is separate.

## Workflow

1. Read [references/build-and-paths.md](references/build-and-paths.md).
2. Edit sources under `src/captive_portal/web-src/`.
3. Keep endpoint expectations aligned with `src/captive_portal/captive_portal.cpp`.
4. Rebuild `src/captive_portal/web-dist/` after source changes.
5. Mention manual verification because the UI is not covered by the current automated tests.

## Rules

- Treat `web-dist` as generated output.
- Preserve the Vite output contract:
  - `index.html`
  - `assets/app.js`
  - `assets/app.css`
- Keep the frontend compatible with the captive portal endpoints:
  - `GET /init-params`
  - `GET /scan-networks`
  - `GET /server-key`
  - `POST /provision`
- Prefer focused UI changes over broad refactors.

## References

- [references/build-and-paths.md](references/build-and-paths.md)
