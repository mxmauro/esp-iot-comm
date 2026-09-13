---
name: repository-file-style
description: Apply shared formatting for CMake, YAML, shell, Markdown, and other handwritten repository text files.
---

# Repository File Style

- Use LF line endings, UTF-8 or plain ASCII, a final newline, and no trailing whitespace in handwritten text. Markdown and reStructuredText may retain intentional trailing spaces for rendering.
- Use 4 spaces in CMake. Keep commands lowercase and arguments logically grouped; keep CMake lines at or below 120 characters where practical.
- Use 2 spaces in YAML and shell scripts. Preserve existing YAML key ordering when practical.
- Keep Markdown concise and consistent with the repository tone. Do not reflow unrelated prose.
- Preserve formatting and encoding in untouched regions. Do not run broad formatting for a focused behavioral change.
