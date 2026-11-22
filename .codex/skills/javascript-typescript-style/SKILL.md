---
name: javascript-typescript-style
description: Apply formatter-first, type-safe JavaScript, TypeScript, and Svelte script conventions to handwritten frontend or library code.
---

# JavaScript and TypeScript Style

Use this skill for handwritten JavaScript, TypeScript, and Svelte script code. Local formatter, linter, framework, and repository
rules decide indentation, quotes, semicolons, line endings, and component structure.

## Formatting and structure

- Run the configured formatter or checker only for files changed by the task. Do not hand-edit generated bundles, framework output,
  or vendored dependencies; regenerate them through the repository workflow when needed.
- Preserve the surrounding module and import/export behavior. For new files or touched structural sections, use this declaration
  order when it does not conflict with local guidance: imports/re-exports; private define-like constants; types/interfaces/classes;
  exported constants and variables followed by private state; then named functions.
- Separate populated declaration sections with a separator such as
  `// -----------------------------------------------------------------------------`, retaining one blank line around it.
  Remove separators adjacent to empty sections. Keep arrow-function constants in the function section.
- Use arrow syntax for named functions. Use brace blocks for control flow and for named or multi-step callbacks. A concise
  expression-bodied callback is acceptable when it is one clear operation and matches local style.
- Within each logical function phase, declare local variables before the executable statements that use them and leave one blank
  line after the declaration block. Do not hoist variables across guards, branches, or loops merely to group declarations; declare
  them at the start of their narrowest logical phase.
- Keep comments sparse and useful: explain protocol, security, state, asynchronous, or UI intent rather than restating syntax.
- For a longer function, use concise intent comments and blank lines to separate distinct validation, parsing, persistence, or
  state-transition phases. Do not comment straightforward assignments or one-step helpers.

## Type safety and runtime boundaries

- Preserve public API and runtime boundaries. Keep browser, Node.js, worker, and framework-specific code isolated according to the
  existing project structure.
- Validate externally supplied data at runtime; static types do not validate JSON, storage, messages, URLs, or network responses.
- Prefer existing typed helpers and domain types over ad hoc casts or untyped conversions. Avoid widening to `any` unless an
  established boundary requires it and its unsafe value is immediately contained.
- Make asynchronous cancellation, pending-operation cleanup, error handling, and UI state transitions explicit. Do not leak
  sensitive values through logs, errors, URLs, or persisted client state.
