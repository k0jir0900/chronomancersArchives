# CLAUDE.md

## Output

- Return code first. Explanation after, only if non-obvious.
- No inline prose. Use comments sparingly - only where logic is unclear.
- No boilerplate unless explicitly requested.

## Code Rules

- Simplest working solution. No over-engineering.
- No abstractions for single-use operations.
- No speculative features or "you might also want..."
- Read the file before modifying it. Never edit blind.
- No docstrings or type annotations on code not being changed.
- No error handling for scenarios that cannot happen.
- Three similar lines is better than a premature abstraction.

## Reusability & Structure

- Evaluate code for multi-section utility: If logic can be used in more than one place, extract it into a separate function or module.
- Variable Passing: Use explicit parameter passing for reusable components.
- Functional Structure: Break down logic into small, focused functions to ensure clean and fast debugging.
- No Monolithic Blocks: Avoid large, single blocks of code; prioritize modularity.

## Review Rules

- State the bug. Show the fix. Stop.
- No suggestions beyond the scope of the review.
- No compliments on the code before or after the review.

## Debugging Rules

- Never speculate about a bug without reading the relevant code first.
- State what you found, where, and the fix. One pass.
- If cause is unclear: say so. Do not guess.

## Simple Formatting

- No em dashes, smart quotes, or decorative Unicode symbols.
- Plain hyphens and straight quotes only.
- Natural language characters (accented letters, CJK, etc.) are fine when the content requires them.
- Code output must be copy-paste safe.

## Development Standards

- Use Docker and Docker Compose for the development environment.
- Provide clear instructions on how to build and run containers.
- Use multi-stage builds to keep images lightweight.

## Security & Secrets Management

- Encrypted Storage: All secrets must be stored in an encrypted, non-recoverable volume mounted at runtime.
- No Hardcoding: Never include secrets in environment variables or Dockerfiles.
- Secret Lifecycle: Provide specific docker exec commands to inject and securely wipe secrets.
- Documentation: Every secret must be documented including its purpose and management command.
- Non-Root Execution: Containers must run as a non-privileged USER with access to the secret volume.

## Operations & Commands

- Add secret: docker exec -it <container_name> sh -c "echo 'value' > /mnt/secrets/key_name"
- Remove secret: docker exec -it <container_name> sh -c "shred -u /mnt/secrets/key_name"