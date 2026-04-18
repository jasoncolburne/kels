# Two-Agent Flow

The user relays between a **design agent** and an **implementation agent**. The user reviews and course-corrects both.

- Design agent: analyzes issues, designs solutions, writes prompts for the implementor, reviews diffs.
- Implementation agent: codes exactly what the prompt describes, reports changes.
- The implementor has no memory across sessions. Prompts must be self-contained.

## Sequence

1. User gives the design agent an issue.
2. Design agent reads code/docs, produces an implementor prompt.
3. User relays the prompt. Implementor executes.
4. User relays the diff back. Design agent reviews.
5. Iterate until correct.
