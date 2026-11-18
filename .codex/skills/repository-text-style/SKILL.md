---
name: repository-text-style
description: Apply formatter- and repository-aware formatting to handwritten configuration, scripts, documentation, and other text files.
---

# Repository Text Style

Use this skill for handwritten CMake, YAML, shell, Markdown, configuration, and similar repository text. Do not use it to normalize generated output or third-party files.

- Read `.editorconfig`, `.gitattributes`, configured formatters, and local guidance first. Preserve the target path's established encoding, line endings, indentation, and key/order conventions when they differ from a catalog default.
- Where no local rule exists, use UTF-8, a final newline, no trailing whitespace, and practical lines of at most 140 characters. Intentional Markdown or reStructuredText line breaks are allowed.
- Keep CMake commands lowercase and arguments logically grouped; keep YAML indentation and ordering consistent with surrounding entries; keep shell syntax and quoting explicit and portable for the shell in use.
- Keep Markdown concise and aligned with the repository's tone. Do not reflow unrelated prose.
- Make formatting changes only where the task requires them. Preserve untouched text, comments, and encoding exactly.
