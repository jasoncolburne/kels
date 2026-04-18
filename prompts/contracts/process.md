# Process

- **Never commit without explicit approval.** Report readiness; wait for the user to say "commit."
- **Don't create files** unless the task requires it. Prefer editing existing files. Ask if unsure.
- **Don't add error handling for impossible scenarios.** Trust internal code. Validate at system boundaries only.
- **Minimal diff.** Change what's asked, nothing more. Don't reformat untouched code, add comments to unchanged code, or clean up unrelated imports.
- **Follow existing patterns.** Read how similar code works before writing a new pattern.
- **Test what you changed.** Run `make`. If the task describes new test expectations, verify them.
- **Long GitHub issue/PR bodies** go in `/tmp/` first, filed with `--body-file`.
