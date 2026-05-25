# Build And Paths

## Source of Truth

- Editable frontend source: `src/captive_portal/web-src/`
- Generated embedded output: `src/captive_portal/web-dist/`
- Runtime HTTP serving: `src/captive_portal/captive_portal.cpp`

## Build Contract

- `src/captive_portal/web-src/vite.config.js` writes to `../web-dist`.
- Output filenames are intentionally stable:
  - `assets/app.js`
  - `assets/app.css`
- `CMakeLists.txt` embeds those exact files plus `index.html`.

## Dev-Server Notes

- `package.json` exposes:
  - `npm run dev`
  - `npm run build`
- Vite mock middleware currently serves:
  - `/scan-networks`
  - `/init-params`
  - `/server-key`
  - `/provision`

## Practical Rule

If the docs and source tree disagree about web paths, trust `CMakeLists.txt`, `idf_component.yml`, and `src/captive_portal/web-src/vite.config.js` because they define the actual build and packaging behavior.
