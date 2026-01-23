# Agent Development Guidelines

This document provides guidelines and conventions for AI agents working on this codebase.

## Production Software Standards

**This is production-grade software.** All code must meet production quality standards:

- **Complete Implementation**: No TODOs, placeholders, or "demonstration" code. Every feature must be fully implemented.
- **Comprehensive Error Handling**: All error paths must be handled properly, with clear error messages and proper error propagation.
- **Full Test Coverage**: All functionality must have comprehensive tests covering happy paths, error cases, and edge conditions.
- **Production-Ready Documentation**: All public APIs must have complete rustdoc with examples, error conditions, and behavioral specifications.
- **Security First**: All security-sensitive operations must be implemented with production-grade security measures.
- **Performance Conscious**: Code must be optimized for production workloads, not just correctness.
- **Observability**: All operations must have appropriate logging, metrics, and tracing for production debugging.

When implementing features:

- Write production code from the start - no prototypes or demos
- Think about failure scenarios and edge cases
- Consider operational concerns (monitoring, debugging, maintenance)
- Implement complete functionality, not partial demonstrations

## Pre-Implementation Checklist

This repository contains conventions, constraints, and decisions that are easy to miss.
Before proposing changes, pull the relevant repo memory docs into context.

Before implementing features, verify:

1. **Read Specifications**: Check `docs/spec/` for relevant documentation
2. Read `docs/constraints.md` (tripwires + hard rules)
3. Read `docs/catalog.md` (what already exists to reuse)
4. Read relevant standards in `docs/standards/` (language/domain specific)
5. **Search Existing Code**: Use semantic_search to find similar implementations
6. **Check Module Structure**: Determine if code belongs in existing module or needs new one
7. **Security Review**: Identify sensitive data (tokens, secrets) requiring special handling
8. **Plan Tests**: Identify test scenarios before writing implementation

## When to consult ADRs (mandatory triggers)

If your change touches any of the following, read the linked ADR(s) referenced from `docs/constraints.md`
and/or search `docs/adr/` by keyword:

### Architecture / boundaries

- cross-boundary integration (services, accounts, networks, tenants)
- auth, identity, permissions
- data storage, encryption, PII
- multi-region/multi-environment behavior
- performance or latency-sensitive paths

### Interfaces

- public API changes
- database schema changes
- message/event contracts
- CLI flags / config formats

### Risky domains

- networking, security, secrets, payments
- build/release pipelines
- migrations and backwards compatibility

## Contribution expectations

- Prefer small diffs
- Reuse existing helpers/modules before adding new ones
- If you introduce a new pattern or constraint, add an ADR and a `docs/constraints.md` entry
- When summarizing changes, link the ADR(s) / standards you relied on

## What to include in responses

When generating code or plans:

- cite which constraints apply
- name the standards followed (formatting, naming, error handling, etc.)
- mention existing modules/helpers used (from `docs/catalog.md`)

## Summary

Following these conventions ensures:

- **Consistency**: Codebase looks like one person wrote it
- **Maintainability**: Easy to find and understand code
- **Quality**: High test coverage and clear documentation
- **Security**: Sensitive data handled properly
- **Performance**: Conscious resource management

When in doubt, look at existing code in the repository as examples of these patterns in practice.
