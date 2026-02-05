# Contributing to queue-runtime

Thank you for your interest in contributing to queue-runtime! This document provides guidelines for contributing to the project.

## Table of Contents

- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Testing Requirements](#testing-requirements)
- [Code Style Guidelines](#code-style-guidelines)
- [Commit Message Format](#commit-message-format)
- [Pull Request Process](#pull-request-process)
- [Code Review Guidelines](#code-review-guidelines)
- [License](#license)

## Development Setup

### Prerequisites

- **Rust**: 1.76 or later (MSRV - Minimum Supported Rust Version)
- **Cargo**: Latest stable version
- **Git**: For version control
- **Optional Tools**:
  - `cargo-watch`: For auto-rebuilding on file changes (`cargo install cargo-watch`)
  - `cargo-nextest`: For faster test execution (`cargo install cargo-nextest`)
  - `cargo-outdated`: For checking dependency updates (`cargo install cargo-outdated`)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/pvandervelde/queue-runtime.git
cd queue-runtime

# Build the crate
cargo build

# Run all tests
cargo test

# Run tests with all features enabled
cargo test --all-features

# Build documentation
cargo doc --no-deps --all-features --open
```

### Development Commands

```bash
# Run tests with watch mode (auto-rerun on changes)
cargo watch -x test

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture

# Run tests with coverage (requires cargo-llvm-cov)
cargo install cargo-llvm-cov
cargo llvm-cov --all-features --html

# Check code without building
cargo check

# Format code
cargo fmt

# Run linter
cargo clippy --all-features -- -D warnings

# Check for outdated dependencies
cargo outdated
```

### Azure Service Bus Testing (Optional)

To test against a real Azure Service Bus instance:

```bash
# Set up Azure Service Bus connection
export AZURE_SERVICEBUS_CONNECTION_STRING="Endpoint=sb://...;SharedAccessKey=..."

# Or use managed identity (when running in Azure)
export AZURE_SERVICEBUS_NAMESPACE="your-namespace"

# Run integration tests (when available)
cargo test --test integration_tests
```

## Development Workflow

### 1. Create a Feature Branch

```bash
# Ensure you're on the master branch
git checkout master
git pull origin master

# Create a new feature branch
git checkout -b feature/your-feature-name
# or for bug fixes
git checkout -b fix/bug-description
```

### 2. Make Changes

- Write code following the [code style guidelines](#code-style-guidelines)
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass locally

### 3. Commit Changes

Use [conventional commits](#commit-message-format) for all commits:

```bash
git add .
git commit -m "feat(client): add support for batch message sending"
```

### 4. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub following the [PR process](#pull-request-process).

## Testing Requirements

### Test Coverage

All contributions must include appropriate tests:

- **New Features**: Must include unit tests and integration tests (if applicable)
- **Bug Fixes**: Must include a test that would have caught the bug
- **Refactoring**: Existing tests must continue to pass
- **Documentation**: Code examples in docs must be tested with `cargo test --doc`

### Test Categories

1. **Unit Tests**: Test individual functions and types in isolation

   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn test_message_creation() {
           let msg = Message::new(Bytes::from("test"));
           assert_eq!(msg.body.len(), 4);
       }
   }
   ```

2. **Integration Tests**: Test interactions between components

   ```rust
   #[tokio::test]
   async fn test_send_and_receive() {
       let client = QueueClientFactory::create_test_client();
       // Test complete workflow
   }
   ```

3. **Doc Tests**: Examples in documentation must be executable

   ````rust
   /// Send a message to a queue.
   ///
   /// ```
   /// use queue_runtime::*;
   ///
   /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
   /// let client = QueueClientFactory::create_test_client();
   /// let queue = QueueName::new("test-queue".to_string())?;
   /// let msg = Message::new(bytes::Bytes::from("Hello"));
   /// client.send_message(&queue, msg).await?;
   /// # Ok(())
   /// # }
   /// ```
   ````

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test file
cargo test --test client_tests

# Run tests with output
cargo test -- --nocapture

# Run tests with coverage report
cargo llvm-cov --html

# Run doc tests only
cargo test --doc
```

### Test Organization

Tests should be in separate files adjacent to the code they test:

- Source file: `src/client.rs`
- Test file: `src/client_tests.rs`

Reference test file from source:

```rust
#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
```

### Test Quality Standards

- **Descriptive Names**: Test names should clearly describe what they verify

  ```rust
  #[test]
  fn test_message_with_empty_body_returns_validation_error() { }
  ```

- **Arrange-Act-Assert Pattern**:

  ```rust
  #[test]
  fn test_example() {
      // Arrange: Set up test data
      let input = "test";

      // Act: Execute the operation
      let result = function_under_test(input);

      // Assert: Verify the outcome
      assert_eq!(result, expected);
  }
  ```

- **Test Independence**: Each test should be independent and not rely on others
- **Edge Cases**: Test boundary conditions, empty inputs, maximum values
- **Error Paths**: Test all error conditions explicitly

## Code Style Guidelines

### Rust Conventions

Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) and project-specific conventions:

#### Naming

- **Modules**: `snake_case` (e.g., `queue_client`, `error_handling`)
- **Types**: `PascalCase` (e.g., `QueueClient`, `MessageId`)
- **Functions**: `snake_case` (e.g., `send_message`, `get_session`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_RETRY_ATTEMPTS`)
- **Lifetimes**: Short, descriptive lowercase (e.g., `'a`, `'msg`)

#### Code Organization

```rust
// Module structure
src/
├── lib.rs              // Public API exports
├── error.rs            // Error types
├── error_tests.rs      // Error tests
├── client.rs           // Client implementation
├── client_tests.rs     // Client tests
├── message.rs          // Message types
└── providers/
    ├── mod.rs          // Provider trait
    ├── azure.rs        // Azure implementation
    └── azure_tests.rs  // Azure tests
```

#### Documentation

All public APIs must have rustdoc comments:

```rust
/// Send a message to the specified queue.
///
/// Messages are sent with at-least-once delivery semantics. The provider
/// will attempt delivery multiple times if transient failures occur.
///
/// # Arguments
///
/// * `queue` - The target queue name
/// * `message` - The message to send
///
/// # Returns
///
/// Returns the message ID assigned by the provider on success.
///
/// # Errors
///
/// Returns `QueueError` if:
/// - Queue does not exist (`QueueNotFound`)
/// - Authentication fails (`AuthenticationFailed`)
/// - Network connectivity issues (`ConnectionFailed`)
///
/// # Example
///
/// ```no_run
/// use queue_runtime::*;
/// use bytes::Bytes;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = QueueClientFactory::create_test_client();
/// let queue = QueueName::new("my-queue".to_string())?;
/// let message = Message::new(Bytes::from("Hello, World!"));
/// let message_id = client.send_message(&queue, message).await?;
/// println!("Sent message: {}", message_id.as_str());
/// # Ok(())
/// # }
/// ```
pub async fn send_message(
    &self,
    queue: &QueueName,
    message: Message,
) -> Result<MessageId, QueueError>;
```

#### Error Handling

- Use `thiserror` for error type derivation
- Provide context for debugging (but never expose secrets)
- Implement retry classification methods

```rust
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("Queue not found: {name}")]
    QueueNotFound { name: String },

    #[error("Authentication failed: {message}")]
    AuthenticationFailed { message: String },
}

impl QueueError {
    /// Returns true if the error is transient and should be retried.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::ConnectionFailed { .. })
    }
}
```

#### Security

- **Never log secrets**: Use custom `Debug` implementations for sensitive types

  ```rust
  impl fmt::Debug for SecretToken {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
          f.debug_struct("SecretToken")
              .field("token", &"<REDACTED>")
              .finish()
      }
  }
  ```

- **Validate inputs**: Sanitize all external data
- **Use type system**: Distinguish validated vs unvalidated data with newtypes

### Formatting

The project uses `rustfmt` for consistent formatting:

```bash
# Format all code
cargo fmt

# Check formatting without modifying files
cargo fmt -- --check
```

### Linting

The project uses `clippy` for additional linting:

```bash
# Run clippy with warnings as errors
cargo clippy --all-features -- -D warnings

# Automatically fix some clippy warnings
cargo clippy --fix --all-features
```

## Commit Message Format

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for automated changelog generation and semantic versioning.

### Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description | Version Bump | When to Use |
|------|-------------|--------------|-------------|
| `feat` | New feature | Minor (0.x.0) | Adding new functionality |
| `fix` | Bug fix | Patch (0.0.x) | Fixing incorrect behavior |
| `docs` | Documentation only | None | README, rustdoc, guides |
| `style` | Code style changes | None | Formatting, whitespace |
| `refactor` | Code refactoring | None | Restructuring without behavior change |
| `perf` | Performance improvement | Patch | Optimizations |
| `test` | Test additions/changes | None | Adding or updating tests |
| `chore` | Build/tooling changes | None | Dependencies, config files |
| `ci` | CI/CD changes | None | GitHub Actions, workflows |

### Scopes

Use the module or component name as scope:

- `client` - QueueClient implementation
- `provider` - Provider trait and implementations
- `azure` - Azure Service Bus provider
- `aws` - AWS SQS provider (when available)
- `message` - Message types and handling
- `session` - Session management
- `error` - Error types and handling
- `config` - Configuration
- `readme` - README updates
- `deps` - Dependency updates

### Examples

**Feature Addition:**

```bash
git commit -m "feat(client): add batch message sending support

Implements batching for improved throughput when sending
multiple messages. Batch size is configurable per provider.

Closes #123"
```

**Bug Fix:**

```bash
git commit -m "fix(azure): correct session lock renewal timing

Session locks were expiring too early due to incorrect
calculation of renewal interval. Now renews at 80% of
lock duration as per Azure recommendations."
```

**Documentation:**

```bash
git commit -m "docs(readme): add configuration examples for AWS

Added AWS SQS configuration section with environment
variable setup and programmatic examples."
```

**Breaking Change:**

```bash
git commit -m "feat(client)!: change QueueClient trait to async

BREAKING CHANGE: All QueueClient methods now return Future
types. Update your code to use .await on all operations.

Migration example:
- let result = client.send_message(queue, msg);
+ let result = client.send_message(queue, msg).await;
```

### Commit Message Guidelines

- **Use imperative mood**: "add feature" not "added feature" or "adds feature"
- **Keep first line under 72 characters**: For better Git log readability
- **Capitalize first letter**: "Add feature" not "add feature"
- **No period at end of subject**: Use period in body paragraphs
- **Separate subject from body**: Use blank line between subject and body
- **Wrap body at 72 characters**: For consistent formatting
- **Explain what and why**: Not how (code shows how)

## Pull Request Process

### Before Submitting

Ensure your PR is ready:

- [ ] All tests pass (`cargo test`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy --all-features -- -D warnings`)
- [ ] Documentation is updated (if adding/changing public APIs)
- [ ] Commit messages follow conventional commits format
- [ ] Branch is up-to-date with `master`

### PR Title and Description

**Title Format**: Use conventional commit format

```
feat(client): add support for batch operations
```

**Description Template**:

```markdown
## Description

Brief description of what this PR does and why.

## Changes

- List specific changes made
- One bullet per significant change
- Include any API changes

## Testing

Describe how you tested these changes:
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed (describe)

## Documentation

- [ ] Public APIs have rustdoc comments
- [ ] Examples updated (if applicable)
- [ ] README updated (if applicable)

## Breaking Changes

List any breaking changes and migration guide (if applicable).

## Related Issues

Closes #123
Relates to #456
```

### PR Size Guidelines

- **Small PRs are better**: Aim for PRs under 400 lines of changes
- **One concern per PR**: Don't mix features, fixes, and refactoring
- **Split large features**: Break into multiple PRs with clear dependencies

### Review Process

1. **Automated Checks**: CI must pass (tests, linting, formatting)
2. **Code Review**: At least one approving review required
3. **Address Feedback**: Respond to all review comments
4. **Squash Commits** (optional): Maintainers may squash on merge for cleaner history

## Code Review Guidelines

### For Authors

- **Be responsive**: Address feedback promptly
- **Be open**: Consider suggestions objectively
- **Ask questions**: If feedback is unclear, ask for clarification
- **Test suggestions**: Try suggestions before rejecting

### For Reviewers

- **Be constructive**: Suggest improvements, don't just criticize
- **Be specific**: Point to exact lines and suggest alternatives
- **Prioritize**: Distinguish blocking issues from nice-to-haves
- **Acknowledge good work**: Positive feedback is valuable too

### Review Checklist

- [ ] **Correctness**: Does the code do what it claims?
- [ ] **Tests**: Are there adequate tests covering the changes?
- [ ] **Documentation**: Are public APIs documented?
- [ ] **Performance**: Are there any obvious performance issues?
- [ ] **Security**: Are inputs validated? Secrets not logged?
- [ ] **Error Handling**: Are errors handled appropriately?
- [ ] **Style**: Does code follow project conventions?
- [ ] **Naming**: Are names clear and consistent?

## Getting Help

- **Documentation**: Check [docs/](docs/) for architecture and design docs
- **Issues**: Search existing issues or create a new one
- **Discussions**: Use GitHub Discussions for questions
- **Specs**: Review [docs/spec/](docs/spec/) for detailed specifications

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
