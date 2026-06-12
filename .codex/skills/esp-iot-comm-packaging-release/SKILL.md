---
name: esp-iot-comm-packaging-release
description: Maintain the esp-iot-comm component release surface. Use when Codex changes CMakeLists.txt, idf_component.yml, embedded captive-portal assets, version metadata, published file inclusion rules, or other packaging details that control what downstream ESP-IDF users build and receive.
---

# Esp Iot Comm Packaging Release

This skill is for changes that affect how the component is built, embedded, versioned, or published through the ESP-IDF component manager.

## Read First

1. Read `AGENTS.md`.
2. Read `CMakeLists.txt`.
3. Read `idf_component.yml`.
4. If captive portal assets changed, read the editable sources under `src/captive_portal/web-src/` and confirm whether `web-dist/` must be regenerated.

## Repository-Specific Facts

- `CMakeLists.txt` embeds exactly:
  - `src/captive_portal/web-dist/index.html`
  - `src/captive_portal/web-dist/assets/app.js`
  - `src/captive_portal/web-dist/assets/app.css`
- `idf_component.yml` excludes:
  - `.codex/**/*`
  - `.vscode/**/*`
  - `AGENTS.md`
  - `build/**/*`
  - `examples/**/*`
  - `src/captive_portal/web-src/**/*`
  - `test/**/*`
- The component declares `idf >=5.5.0,<7.0.0`.
- Linux simulator builds are intentionally unsupported in `CMakeLists.txt`.

## Update Workflow

1. Determine whether the change affects local build behavior, published package contents, or both.
2. Keep `CMakeLists.txt` and `idf_component.yml` synchronized when a file is newly embedded, newly excluded, renamed, or moved.
3. When web UI sources change, regenerate `web-dist/` instead of patching built assets by hand.
4. Update version metadata only when the task explicitly changes release semantics.
5. Check whether README or docs installation guidance must change when dependency, target, or packaging rules change.

## Guardrails

- Do not accidentally publish dev-only files, tests, or source-only frontend files.
- Do not remove embedded asset paths without replacing every consumer that expects them.
- Keep packaging edits minimal; a small manifest mistake can break downstream `idf.py reconfigure` or component-manager installs.
- If verification cannot be run locally, call out the exact packaging or build risk that remains.
