---
name: embedded-cpp-style
description: Apply a safe, repository-aware C and C++ style for ESP-IDF and comparable embedded applications and libraries.
---

# Embedded C/C++ Style

Use this skill for handwritten embedded C/C++ source and headers. Local component guidance, toolchain rules, and established public API names take precedence.

## Layout and declarations

- Use the repository's established encoding and line endings. Where no local convention exists, use four spaces, no tabs, a final newline, and practical lines of at most 140 characters.
- Use Allman braces for classes, functions, control-flow blocks, ordinary structs, unions, and `catch`/`else`/`do` continuations when that matches the repository. Always brace control-flow bodies. Preserve compact `typedef struct`, `typedef enum`, `namespace`, and `extern "C"` forms where established.
- Keep includes, blank lines, section separators, wrapping, preprocessor indentation, and file-local helper placement consistent with surrounding code. Do not reorder includes without a task reason.
- Use explicit types except where an iterator-style loop or init-statement makes `auto` obvious. Initialize variables at declaration or immediately before use, and prefer early validation/failure returns.
- Preserve `#pragma once`, `extern "C"` guards, `noexcept`, `final`, deleted operations, bitfields, packed declarations, and other API or ABI qualifiers.

## C/C++ and preprocessor conventions

- Preserve the repository's C-facing versus C++ naming patterns and public/module prefixes. Do not rename established symbols for uniformity.
- Wrap long declarations, calls, and expressions only when necessary; preserve the repository's continuation and operator placement style.
- Preserve required multiline macro continuations and alignment. Do not rewrap a macro in a way that changes expansion, evaluation, or conditional-compilation behavior.
- Use concise comments for non-obvious constraints, ownership, timing, hardware, or concurrency intent—not for straightforward syntax.

## Embedded safety

- Follow the established ESP-IDF/FreeRTOS error, synchronization, and component-registration patterns. Do not introduce exceptions, RTTI-dependent code, or heavyweight facilities into constrained paths unless the existing design already relies on them.
- Treat tasks and shared objects as concurrent unless ownership is explicit. Do not hold locks or critical sections across I/O, allocation, delays, callbacks, or blocking RTOS calls.
- Make task parameter lifetime, queue/buffer ownership, shutdown signaling, and component/package boundaries explicit. Use platform-specific security guidance for cryptography, provisioning, storage, or transport changes.
