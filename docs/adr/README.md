# ADRs (Architecture Decision Records)

This folder contains ADRs documenting important architectural decisions.

## ADR Naming and Numbering

Format: `ADR-NNN-short-title.md` (e.g., `ADR-001-hexagonal-architecture.md`)

- Use sequential three-digit numbers starting at 001
- Use hyphens between number and title
- Keep titles concise (2-5 words)

## When to Create an ADR

Create an ADR when you make a decision that:
- Affects the overall architecture or system design
- Has significant trade-offs or consequences
- Will be referenced frequently in code reviews
- Could be reconsidered in the future (document why we chose this path)

Do NOT create ADRs for:
- Implementation details that don't affect architecture
- Reversible decisions (use code comments instead)
- Temporary workarounds

## ADR Process

1. Copy [ADR_TEMPLATE.md](ADR_TEMPLATE.md) to `ADR-NNN-short-title.md`
2. Fill in all sections: Context, Decision, Consequences, Alternatives, Implementation notes, Examples, References
3. Link the ADR from [../AGENTS.md](../AGENTS.md) under relevant section
4. Add entry to [../constraints.md](../constraints.md) with a brief summary if applicable
5. Get review before merging

## Existing ADRs

- [ADR-001: Hexagonal Architecture](./ADR-001-hexagonal-architecture.md)
- [ADR-002: Session/Ordering Abstraction](./ADR-002-session-ordering-abstraction.md)
- [ADR-003: Async-First Design](./ADR-003-async-first.md)
- [ADR-004: Runtime Provider Selection](./ADR-004-runtime-provider-selection.md)
