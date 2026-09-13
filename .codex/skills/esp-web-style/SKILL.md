---
name: esp-web-style
description: Apply the JavaScript, TypeScript, and Svelte style for the esp-iot-comm captive portal web UI. Use when editing frontend source, not generated web assets.
---

# Esp Web Style

Use this skill for `src/captive_portal/web-src/`. Also follow `repository-file-style` for line endings, encoding, and whitespace.

- Use 4 spaces and preserve the surrounding file's quote, semicolon, wrapping, and blank-line conventions; this repository has no JavaScript formatter or linter that defines replacements.
- Preserve the existing Svelte, Vite, and ES-module structure. Keep UI source under `web-src` and treat `web-dist` as generated output.
- Keep edits focused. Do not normalize unrelated frontend code or hand-edit generated `web-dist` files.
- Use concise comments only for non-obvious UI, protocol, or security intent.
