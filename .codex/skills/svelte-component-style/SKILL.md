---
name: svelte-component-style
description: Apply Svelte component and Svelte 5 reactive-state conventions while preserving the repository's framework and formatting choices.
---

# Svelte Component Style

Use this skill for handwritten Svelte components. Also use `javascript-typescript-style` for JavaScript or TypeScript code inside script blocks. Local framework, formatter, accessibility, and component-library rules take precedence.

- Keep `$state`, `$derived`, `$effect`, and related reactive declarations in the state/variables section appropriate to their visibility and declaration kind.
- Keep event handlers, asynchronous actions, and other named callbacks in the function section after declarations. Preserve declaration order when moving code would change initialization, temporal-dead-zone, export, or reactive behavior.
- Keep component markup, styles, slots, snippets, and transitions consistent with the surrounding component and local framework conventions. Do not introduce a store, routing, persistence, or dependency layer without a concrete task requirement.
- Keep interactive controls keyboard-accessible, visibly labelled, and associated with their validation errors according to the local component system.
- Treat browser-facing data as untrusted. Keep protocol encoding, validation, and security-sensitive state outside presentation components where the repository has an application/data layer for them.
