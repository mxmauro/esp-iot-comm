---
name: embedded-cpp-style
description: Apply the shared C and C++ coding style for ESP-IDF applications and libraries. Use when editing C/C++ source or headers; use repository guidance for module-specific API names.
---

# Embedded C/C++ Style

Use this skill for handwritten C/C++ source and headers. Also follow `repository-file-style` for line endings, encoding, and support-file formatting. Preserve established module and public API prefixes from the repository guidance.

## Layout and declarations

- Use 4 spaces and no tabs. Keep C/C++ lines at or below 140 characters where practical; do not pad lines to that limit.
- Use Allman braces for classes, functions, control-flow blocks, ordinary structs, unions, and `catch`/`else`/`do` continuations. Always brace control-flow bodies. Never collapse short functions, blocks, conditions, loops, cases, or lambdas onto one line merely for brevity.
- Keep `{` on the declaration line for `typedef struct` and `typedef enum`. Keep `namespace X {` and `extern "C" {` compact, with no scope-only indentation. Comment every namespace closing brace.
- Do not add scope-only indentation to `public:`, `private:`, or `protected:`. Put a class or struct declaration on the line after its `template <...>` declaration.
- Attach pointer declarators to the type (`void* value`). Preserve `noexcept`, `final`, deleted operations, bitfields, packed declarations, and equivalent API qualifiers.
- Use explicit types except when iterator-style loops or an init-statement make `auto` obvious. Initialize variables at declaration or immediately before use, and prefer early validation/failure returns.
- Keep file-local `static` helpers near the beginning of their translation unit, before main function bodies. Keep `#pragma once` and required `extern "C"` guards.

## Wrapping, alignment, and whitespace

- Keep one blank line between function definitions. Use blank lines and existing separator comments for logical sections; do not introduce excessive empty space or reflow comments.
- Do not reorder includes. Keep local/project headers first, then internal project headers where present, then external, C, and ESP-IDF headers.
- Wrap parameter lists, calls, declarations, and expressions only when needed. Pack items while they fit; align continuation text one character after the outer opening parenthesis. Keep binary operators with the preceding expression when wrapping.
- Indent `case` labels inside `switch` blocks and keep each `break;` on its own line.
- Align consecutive struct member names after their types, but never across a blank line or comment. Do not type/name-align function-local variables or constants.
- Align consecutive value-bearing `#define` directives and constant definitions without crossing blank lines or comments. Use one space before an inline comment; never column-align trailing comments.

## Preprocessor and macros

- Indent nested conditional preprocessor directives before `#` one level per enclosing conditional.
- Preserve every required multiline macro continuation. Align its `\` characters at a shared content-driven column, not at column 140. Do not let rewrapping remove a continuation.

## Naming and expressions

- Use PascalCase for ordinary C++ types, `*_t` for C-facing types, `*_s`/`*_e` for C struct/enum tags, and lower-camel case for C functions. Preserve established lower-case library types and existing public/module prefixes instead of renaming for consistency.
- Add sparse comments for non-obvious intent or constraints, not narration of obvious statements.
- Add parentheses to clarify mixed `&&`/`||` expressions and unary negation in larger expressions. Do not add redundant parentheses to homogeneous boolean chains.
