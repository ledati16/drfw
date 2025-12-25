# LLM Agent Guidelines & Coding Standards

This document outlines universal best practices for LLM-based coding assistants (Claude Code, Gemini, etc.) to ensure high-quality, maintainable, and robust software engineering.

## 1. Workflow & Coordination
- **Verification Cycle**: Always validate changes using project-specific build, format, and test tools before committing.
- **Atomic Commits**: Prefer many small, reversible, and semantically logical commits over single monolithic changes.
- **Reverse Mitigation**: Do not revert changes unless they cause regression or were explicitly requested; fix forward whenever possible.

## 2. Code Quality Standards

### Linting & Static Analysis
- **Strict Compliance**: Adhere to the project's configured linting rules (e.g., Pedantic Clippy for Rust, Ruff for Python).
- **Justified Suppressions**: Avoid `#[allow(...)]` or similar suppressions unless the violation is a deliberate architectural trade-off. Every suppression must be documented with a rationale.
- **Refactor over Ignore**: When a warning can be fixed through better design, always prefer refactoring over suppression.

### Documentation Requirements
- **Semantic Documentation**: Document *why* something is done, especially for complex logic, rather than just *what*.
- **Backticks for Technical Terms**: Use backticks for all technical identifiers (variables, functions, tools, environment variables).
- **Result/Panic Documentation**: Public functions returning errors or capable of panicking must explicitly document those conditions.

### Modern Coding Patterns
- **Safety First**: Avoid unsafe constructs or "defensive" unwrapping in production paths.
- **Efficiency**: Prefer in-place modifications (e.g., `clone_from`) over reassignments when possible.
- **Let-Else / Early Return**: Use guard clauses and `let-else` patterns to keep the primary logic at the lowest possible indentation level.
- **Encapsulation**: Default to private visibility; only widen access as strictly required by the architecture.

## 3. Architecture & Safety Patterns

### Async vs. Blocking
- **Worker Isolation**: Never execute blocking I/O or heavy computation directly in an async context. Use dedicated thread pools (e.g., `spawn_blocking`) to keep the runtime responsive.
- **Event-Driven UI**: In terminal or graphical interfaces, prioritize event-driven rendering with frame-rate limiting to ensure low input latency and efficient CPU usage.

### Data Integrity & Safety
- **Atomic Writes**: Important configuration or state files should be written to a temporary file first, synced to disk, and then atomically renamed to the target path to prevent corruption.
- **Resource Cleanup**: Use the "Guard" or RAII pattern (e.g., `Drop` implementation) to ensure system resources (sockets, PID files, terminal modes) are cleaned up even during panics.
- **Process Isolation**: When integrating with external system tools, prefer process isolation (shelling out) over unsafe FFI bindings if the library is not async-native or could compromise the daemon's stability.

### Borrow Checker / Snapshot Pattern
- When needing simultaneous immutable and mutable access to a shared structure:
  1. Snapshot the required read-only data first (clone or copy).
  2. Let immutable borrows go out of scope.
  3. Perform mutable updates or rendering using the snapshot.

## 4. Testing Standards

### Test Coverage Requirements
- **Unit Tests**: All validation logic, error handling paths, and core business logic must have unit tests.
- **Property-Based Tests**: Use `proptest` or similar for fuzzing critical validation functions (input sanitization, parsers, etc.). Property tests have caught real security bugs (e.g., Unicode bypass in interface validation).
- **Integration Tests**: For privileged operations (like `nftables` verification), implement graceful skip logic when privileges are unavailable:
  ```rust
  if !verify_result.success && verify_result.errors.iter()
      .any(|e| e.contains("Operation not permitted")) {
      eprintln!("Skipping test: requires elevated privileges");
      return;
  }
  ```
- **Strict Isolation**: Tests must never touch real user data or environment configuration. Always use temporary directories and isolate environment variables (XDG paths, etc.).
- **Mock External State**: Use mock servers or programmatic stubs to test protocol logic and external IPC without requiring a live environment.
- **Parameterized Testing**: Use table-driven tests to cover edge cases and varied inputs efficiently.
- **Safety Verification**: Use automated scripts to verify that the test suite does not "leak" into the host system.

### Test Organization
- Separate test modules: `tests` (unit), `property_tests` (fuzzing), `integration_tests` (full-stack)
- Document privilege requirements in module-level docs for integration tests
- Ensure CI/CD can run in unprivileged environments (tests skip, not fail)

## 5. Security Practices

### Input Validation & Sanitization
- **Centralized Validators**: Create dedicated validation modules (e.g., `validators.rs`) for all external inputs.
- **Allowlist, Not Blocklist**: Validate by explicitly allowing safe characters, not by blocking known-bad ones.
  ```rust
  // Good: Explicit allowlist
  c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')

  // Bad: Blocklist approach
  !c.is_control() && c != '$' && c != '`' // Incomplete, will miss edge cases
  ```
- **ASCII-Only for System Identifiers**: Interface names, command arguments, and system identifiers must use `is_ascii_alphanumeric()`, not `is_alphanumeric()` (which allows Unicode).
- **Length Limits**: Enforce system-level constraints early (e.g., 15 chars for interface names, 64 for labels).
- **Shell Metacharacter Removal**: Strip or reject: `$`, `` ` ``, `|`, `&`, `;`, `<`, `>`, `\n`, `\r`, quotes.
- **Validation at Boundaries**: Validate immediately when data enters the system (user input, file parsing, IPC), not deep in business logic.

### Command Injection Prevention
- **Never Interpolate User Input into Shell Commands**: Use `Command::args()` with direct arguments, not string interpolation.
  ```rust
  // Good: Safe argument passing
  Command::new("nft").args(["--json", "-f", "-"])

  // Bad: Command injection risk
  Command::new("sh").args(["-c", &format!("nft -f {}", user_file)])
  ```
- **Temporary Files for Sensitive Operations**: Use `tempfile::NamedTempFile` with secure permissions instead of predictable paths:
  ```rust
  let mut temp = NamedTempFile::new()?;
  #[cfg(unix)]
  temp.as_file().set_permissions(Permissions::from_mode(0o600))?;
  ```
- **Avoid Path Traversal**: Use `Path::canonicalize()` and verify paths stay within allowed directories.

### File System Security
- **Permissions Before Content**: Set restrictive permissions (`0o600` for files, `0o700` for dirs) BEFORE writing sensitive data:
  ```rust
  // Good: Permissions set atomically on creation
  OpenOptions::new()
      .create(true)
      .write(true)
      .mode(0o600)  // Set BEFORE any data is written
      .open(&path)?;

  // Bad: Window where file is world-readable
  File::create(&path)?;
  set_permissions(&path, 0o600)?;  // Too late!
  ```
- **Atomic Writes for Config Files**: Use temp file + rename pattern to prevent corruption/TOCTOU:
  ```rust
  let temp = NamedTempFile::new_in(parent_dir)?;
  temp.write_all(data)?;
  temp.persist(&final_path)?;  // Atomic rename
  ```
- **Least Privilege**: Set restrictive filesystem permissions (e.g., `0o600` for user-specific sockets/configs) immediately upon creation.
- **Ownership Verification**: Before performing sensitive operations (like deleting a stale socket), verify the file type and owner UID.

### Privilege Escalation Safety
- **Minimize Elevated Code Paths**: Keep privileged operations isolated in dedicated modules (e.g., `elevation.rs`).
- **Validate BEFORE Elevation**: Run `nft --check` (syntax validation) before attempting elevated apply.
- **Audit All Privileged Operations**: Log all firewall rule applications, system saves, and privilege escalations with timestamps and outcomes.
- **Snapshot Before Modify**: Always capture current state before applying changes for rollback capability.

### Error Handling & Information Disclosure
- **User-Friendly Error Messages**: Translate technical errors into actionable messages:
  ```rust
  // Good: Actionable for end users
  "Permission denied. Ensure pkexec is configured correctly."

  // Bad: Technical jargon
  "EACCES: nft command failed with exit code 1"
  ```
- **Avoid Information Leakage**: Don't expose internal paths, stack traces, or system details to untrusted parties.
- **Structured Error Types**: Use `thiserror` for consistent error handling with user-facing translation layer.

## 6. Firewall-Specific Patterns (nftables/DRFW)

### Rule Ordering & Performance
- **Base Rules First**: Order rules by frequency to minimize unnecessary processing:
  1. Loopback (most common, bypass all checks)
  2. Drop invalid packets (avoid wasting cycles on malformed traffic)
  3. Established/related connections (bulk of traffic)
  4. ICMP (network diagnostics)
  5. User-defined rules
  6. Default policy (drop)

### Snapshot & Rollback
- **Checksum Validation**: Compute SHA-256 checksums of snapshots to detect tampering.
- **Structure Validation**: Verify snapshot JSON contains required `nftables` array and table operations before restoration.
- **Single Privilege Prompt**: Combine snapshot capture + apply in one elevated operation to reduce user friction.

### Integration with nftables
- **JSON API Only**: Use `nft --json` for all operations to enable structured parsing and error handling.
- **Verification Before Apply**: Always run `nft --check` to catch syntax errors before applying to live firewall.
- **Graceful Privilege Handling**: Detect and handle permission errors gracefully (skip tests, show helpful messages).

## 7. Audit Logging

### What to Log
- **All Privileged Operations**: Apply rules, revert to snapshot, save to system
- **Outcomes**: Success/failure, error messages, rule counts
- **Metadata**: Timestamps (UTC), event types, context (which rules, source IPs, interfaces)

### Log Format
- **Structured JSON Lines**: One event per line for easy parsing and log rotation.
- **No Sensitive Data**: Don't log passwords, API keys, or private network details.
- **Tamper Evidence**: Consider append-only permissions (`0o600` with appropriate ACLs).

### Log Location
- **User State Directory**: `~/.local/state/drfw/audit.log` (respects XDG Base Directory spec)
- **Atomic Appends**: Use `OpenOptions::append()` for concurrent safety.

## 8. Error Translation & UX

### Translation Patterns
```rust
impl Error {
    pub fn user_message(&self) -> String {
        match self {
            Error::Nftables { message, .. } => Self::translate_nftables_error(message),
            Error::Validation { field, message } => format!("{field}: {message}"),
            // ... provide context-specific guidance
        }
    }
}
```

### Guidelines
- **Suggest Solutions**: "Try installing nftables: `sudo apt install nftables`"
- **Avoid Technical Jargon**: Translate "netlink cache initialization failed" → "Permission denied. Run with elevated privileges."
- **Progressive Detail**: Show concise message to user, log detailed technical error for debugging.
