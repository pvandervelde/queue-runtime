# Contributing to queue-runtime

Thank you for your interest in contributing to queue-runtime!

## Development Setup

### Prerequisites

- **Rust**: 1.70 or later
- **Cargo**: Latest stable version
- **Git**: For version control

### Building the Project

```bash
# Clone the repository
git clone https://github.com/pvandervelde/queue-runtime.git
cd queue-runtime

# Build the crate
cargo build

# Run tests
cargo test

# Run linters
cargo clippy -- -D warnings
cargo fmt -- --check
```

## Commit Message Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for automated changelog generation and semantic versioning.

### Commit Message Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Commit Types

| Type | Description | Version Bump |
|------|-------------|--------------|
| `feat` | New feature | **Minor** |
| `fix` | Bug fix | **Patch** |
| `perf` | Performance improvement | Patch |
| `refactor` | Code refactoring | Patch |
| `docs` | Documentation changes | None |
| `test` | Test additions/changes | None |
| `chore` | Build/tooling changes | None |
| `ci` | CI/CD changes | None |
| `style` | Code style changes | None |

### Breaking Changes

To trigger a **major version bump**, add `BREAKING CHANGE:` in the commit footer or use `!` after the type:

```bash
feat(auth)!: change authentication interface

BREAKING CHANGE: Authentication now requires async/await pattern
```

## Code Quality

All code must:
- Pass `cargo test`
- Pass `cargo clippy -- -D warnings`
- Be formatted with `cargo fmt`
- Include rustdoc comments for public APIs
- Include tests for new functionality

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear commit messages
3. Ensure all tests pass and code is formatted
4. Update documentation as needed
5. Submit a pull request with description of changes

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
