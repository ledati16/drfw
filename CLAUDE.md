# DRFW Development Standards

**Purpose:** Core development guidelines for LLM agents and contributors working on DRFW.

**Principles:** Security-first, performance-conscious, test-driven, maintainable code.

---

## 1. Code Quality

### Linting & Static Analysis
- **Strict compliance:** Adhere to Clippy pedantic warnings
- **No suppressions without rationale:** Every `#[allow(...)]` must have a documented reason
- **Refactor over suppress:** Fix warnings through better design, not suppression

### Documentation Standards
- **Public APIs:** All public functions require doc comments with:
  - Purpose and behavior
  - Arguments and return values
  - Error conditions
  - Example usage for non-trivial cases
- **Complex logic:** Document **why**, not what (code shows what)
- **Error semantics:** Functions that can fail must document all failure modes
- **Technical terms:** Use backticks for identifiers (`nft`, `pkexec`, `DRFW_TEST_NO_ELEVATION`)

### Modern Rust Patterns
- **Safety first:** No `unwrap()` in production paths; use `?` or `expect()` with context
- **Early returns:** Use `let-else` and guard clauses to minimize indentation
- **Visibility:** Default to private; widen only when architecturally required
- **Efficiency:** Prefer in-place operations (`clone_from`) over reallocations

### DRY Principle Enforcement

**Extract repeated patterns into utilities:**

```rust
// ❌ BAD: Same pattern in 4 functions
pub fn blocking_wrapper_1() -> Type1 {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.block_on(async_fn_1())
    } else {
        tokio::runtime::Runtime::new()
            .expect("Failed to create runtime")
            .block_on(async_fn_1())
    }
}

// ✅ GOOD: Extract to utility (see src/utils.rs:block_on_async)
pub fn blocking_wrapper_1() -> Type1 {
    crate::utils::block_on_async(async_fn_1())
}
```

**When to extract:**
- Pattern used 3+ times
- Pattern is complex (5+ lines)
- Pattern could introduce bugs if inconsistently modified

**When NOT to extract:**
- Pattern is trivial (1-2 lines)
- Extraction would obscure intent
- Pattern has subtle differences between uses

### File Size Guidelines

- **Single file limit:** ~4000 lines (e.g., `app/view.rs` is at this threshold)
- **When to split:** Consider submodules when a file exceeds 3000 lines with clear logical sections
- **Module structure:** Group related functionality (`view/rules.rs`, `view/settings.rs`, `view/modals.rs`)
- **Trade-off:** Balance between too many small files vs monolithic files

**Note:** This is a soft guideline, not a hard rule. Prioritize logical cohesion over arbitrary line counts.

---

## 2. Error Handling

### Error Types
Use `thiserror` for structured, actionable errors:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("Invalid profile name: {0}")]
    InvalidName(String),

    #[error("Profile not found: {0}")]
    NotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
```

### User-Facing Messages
- **Translate technical errors:** "Permission denied. Run with elevated privileges." not "EACCES: exit code 1"
- **Provide solutions:** "Try installing nftables: `sudo apt install nftables`"
- **No internal details:** Don't expose stack traces, paths, or system info to users
- **Consistent format:** Use `Error::user_message()` method for translation layer

### Error Propagation
- **Public APIs:** Always return `Result` with specific error types
- **Internal helpers:** `Option` acceptable for truly optional values
- **Never panic:** Except in `main()` for fatal initialization errors
- **Context on errors:** Use `.map_err()` to add context when propagating

---

## 3. Security

### Input Validation
**Centralized validators** in `src/validators.rs`:

```rust
// ✅ Allowlist approach
pub fn sanitize_label(input: &str) -> String {
    input.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | ':'))
        .take(64)
        .collect()
}

// ❌ Blocklist approach - incomplete
fn bad_sanitize(input: &str) -> String {
    input.chars().filter(|c| !matches!(c, '$' | '`')).collect()
}
```

**Requirements:**
- **ASCII-only for system identifiers:** Use `is_ascii_alphanumeric()`, not `is_alphanumeric()`
- **Enforce limits early:** Interface names (15 chars), labels (64 chars), ports (1-65535)
- **Validate at boundaries:** Parse user input, files, IPC immediately—not in business logic

### Command Injection Prevention
```rust
// ✅ Safe: Direct argument passing
Command::new("nft").args(["--json", "-f", "-"])

// ❌ Unsafe: Shell interpolation
Command::new("sh").args(["-c", &format!("nft -f {}", user_file)])
```

**Never** interpolate user input into shell commands. Use `Command::args()` exclusively.

### File System Security

**Permissions before content:**
```rust
#[cfg(unix)]
{
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o600)  // Set BEFORE writing
        .open(&path)?
}
```

**Atomic writes for critical files:**
```rust
use tempfile::NamedTempFile;

let mut temp = NamedTempFile::new_in(parent_dir)?;
temp.write_all(data)?;
temp.as_file().sync_all()?;  // Force to disk
temp.persist(&final_path)?;   // Atomic rename
```

**Required for:** Config files, profiles, snapshots, audit logs

**Windows note:** Document ACL requirements since Unix permissions don't apply

---

## 4. Privilege Escalation

### Elevation Strategy
Automatic fallback based on environment:

1. **Preferred:** `run0` (systemd v256+) - No SUID, better security
2. **CLI:** `sudo` for terminal environments
3. **GUI:** `pkexec` for graphical authentication

```rust
fn create_elevated_command(args: &[&str]) -> Result<Command> {
    if binary_exists("run0") {
        return Ok(Command::new("run0").arg("nft").args(args));
    }

    let is_tty = nix::unistd::isatty(std::io::stdin())?;
    let tool = if is_tty { "sudo" } else { "pkexec" };
    Ok(Command::new(tool).arg("nft").args(args))
}
```

### Security Requirements
- **Validate before elevation:** Run `nft --check` before `pkexec nft -f`
- **Timeout protection:** 2-minute default maximum
- **Error translation:** Map exit codes to user actions (126=cancelled, 127=auth failed)
- **Audit logging:** Log all privileged operations with timestamps
- **Test bypass:** `DRFW_TEST_NO_ELEVATION=1` for unit tests

### Rejected Approaches
**Do not:**
- Implement custom auth dialogs (security complexity, maintenance burden)
- Use PAM directly (synchronous API conflicts with async GUI)
- Pipe passwords to stdin (pkexec doesn't support this by design)
- Add NOPASSWD sudoers rules (bypasses authentication)

---

## 5. Async Architecture

### Worker Isolation
**Never** block the async runtime:

```rust
// ❌ Blocks event loop
async fn bad_handler() {
    std::thread::sleep(Duration::from_secs(5));  // Freezes UI
}

// ✅ Uses dedicated thread pool
async fn good_handler() {
    tokio::task::spawn_blocking(|| {
        std::thread::sleep(Duration::from_secs(5));
    }).await?
}
```

### Borrow Checker Pattern
When needing simultaneous immutable and mutable access:

```rust
// 1. Snapshot read-only data
let cached_value = self.expensive_field.clone();

// 2. Immutable borrows go out of scope

// 3. Perform mutable updates using snapshot
self.modify_state(cached_value);
```

---

## 6. Testing

### Coverage Requirements
- **Unit tests:** All validators, error paths, business logic
- **Property tests:** Use `proptest` for fuzzing validators (catches Unicode bypasses, edge cases)
- **Integration tests:** Full workflows with graceful privilege skipping
- **Environment safety:** Never touch real user data; use temp dirs and `DRFW_TEST_NO_ELEVATION=1`

### Test Patterns
```rust
#[test]
fn test_validator() {
    assert_eq!(sanitize_label("Valid_Name-123"), "Valid_Name-123");
    assert_eq!(sanitize_label("Bad$Chars"), "BadChars");
    assert_eq!(sanitize_label(&"x".repeat(100)).len(), 64);
}

#[tokio::test]
async fn test_elevated_operation() {
    unsafe { std::env::set_var("DRFW_TEST_NO_ELEVATION", "1"); }

    let result = apply_rules().await;
    assert!(result.is_ok());

    unsafe { std::env::remove_var("DRFW_TEST_NO_ELEVATION"); }
}
```

### CI/CD Compatibility
- Tests must **skip** (not fail) when run without privileges
- Check for "Operation not permitted" in stderr
- Document privilege requirements in module-level docs

### TODO Comment Hygiene

- **Mark phase/completion:** `TODO (Phase 6): Wire up to diagnostics viewer`
- **Update or remove:** Review all TODOs after completing phases
- **Track separately:** Consider using GitHub Issues for long-term TODOs instead of code comments
- **Outdated TODOs:** When features are implemented differently than planned, update comments to reflect actual implementation (see `audit.rs:138` for example of proper update)

---

## 7. Iced GUI Framework

### Styling Pattern (CRITICAL)
**Always use closures, never implement `Catalog` traits:**

```rust
// ✅ Correct: Closure-based styling
button("Save")
    .style(|theme: &AppTheme, status| {
        button::Style {
            background: Some(theme.accent.into()),
            text_color: theme.fg_on_accent,
            // ...
        }
    })

// ❌ Wrong: Implementing Catalog for app themes
impl button::Catalog for AppTheme {  // Causes 100+ compiler errors
    type Class<'a> = ButtonClass;
    fn style(&self, ...) -> Style { ... }
}
```

**Why:** `Catalog` traits are for widget library authors, not applications. Implementing them causes trait ambiguity and type inference failures.

### UI Styling Reference
**Before modifying UI:** Read `STYLE.md` sections on:
- Semantic color system
- Centralized button styles (`primary_button`, `danger_button`, etc.)
- Shadow system (shadows break with gradients)
- Modal/tooltip patterns

**Never:**
- Create inline button styles (use `ui_components.rs` functions)
- Use gradients on interactive elements (breaks shadows in Iced 0.14)
- Modify style functions without checking all call sites

---

## 8. Performance Optimization

### Critical Principle
Iced calls `view()` at 30-60 FPS. **Never compute in `view()`:**

```rust
// ❌ Runs 60 times/second
pub fn view(&self) -> Element {
    let highlighted = syntax_highlight(&self.text);  // BAD
    container(highlighted).into()
}

// ✅ Compute once in update()
fn update(&mut self, msg: Message) {
    self.cached_highlighted = syntax_highlight(&self.text);
}

pub fn view(&self) -> Element {
    container(&self.cached_highlighted).into()  // Just reference
}
```

### Optimization Patterns
**Cache in state:**
- Lowercase search strings (`.to_lowercase()` once per keystroke)
- Filtered/sorted collections (once per data change)
- Syntax highlighting tokens (once per text change)

**Pre-allocate collections:**
```rust
let mut cards = Vec::with_capacity(filtered_rules.len());
let mut output = String::with_capacity(estimated_size);
```

**Avoid allocations:**
```rust
// ❌ Allocates every frame
let text = format!("{}-{}", start, end);

// ✅ Stack buffer
let mut buf = String::with_capacity(12);
write!(&mut buf, "{}-{}", start, end).ok();
```

**Debounce file saves:**
```rust
// ❌ Excessive disk I/O
Message::SettingChanged => {
    self.setting = value;
    self.save_config();  // Disk write on every change!
}

// ✅ Debounced saves with dirty flag
Message::SettingChanged => {
    self.setting = value;
    self.mark_config_dirty();  // Just set flag
}

// Subscription auto-saves after 500ms of no changes
if self.config_dirty {
    iced::time::every(Duration::from_millis(100))
        .map(|_| Message::CheckConfigSave)
} else {
    iced::Subscription::none()
}
```

### Profiling Before Optimizing
1. Use real workloads (100+ rules, not 5)
2. Build with `--release` for accurate measurements
3. Profile with `cargo flamegraph` to find actual bottlenecks
4. Don't optimize cold paths (initialization code)

---

## 9. nftables Integration

### JSON API Only
```rust
// ✅ Structured parsing
Command::new("nft").args(["--json", "list", "ruleset"])

// ❌ Text parsing (fragile)
Command::new("nft").args(["list", "ruleset"])
```

### Validation Workflow
1. **Syntax check:** `nft --json --check -f -` (no elevation needed)
2. **Capture snapshot:** Current state for rollback
3. **Apply with elevation:** `run0/sudo/pkexec nft -f -`
4. **Verify state:** Confirm rules applied correctly

### Rule Ordering
Optimize for common traffic patterns:
1. Loopback (bypass all checks)
2. Invalid packet drops (avoid wasted cycles)
3. Established/related connections (bulk traffic)
4. ICMP (diagnostics)
5. User-defined rules
6. Default policy

---

## 10. Audit Logging

### Requirements
- **Format:** JSON Lines (one event per line)
- **Location:** `~/.local/state/drfw/audit.log` (XDG compliant)
- **Permissions:** `0o600` on creation (user read/write only)
- **Contents:** Timestamps (UTC), event type, success/failure, error messages
- **Exclude:** Passwords, API keys, private network details

### Events to Log
- Rule applications (success/failure, rule count)
- Snapshot operations (save/restore)
- Profile operations (create/delete/switch)
- Settings changes
- Auto-revert events (confirmed/timed out)

```rust
pub async fn log_apply(
    enable_event_log: bool,
    rule_count: usize,
    enabled_count: usize,
    success: bool,
    error: Option<String>,
) {
    if !enable_event_log { return; }

    let event = AuditEvent::new(
        EventType::ApplyRules,
        success,
        json!({ "rule_count": rule_count, "enabled_count": enabled_count }),
        error,
    );
    audit.log(event).await.ok();
}
```

---

## 11. Firewall Features

### Implemented
- Protocol filtering (TCP, UDP, ICMP, ICMPv6, Any)
- Port filtering (single or range)
- Source IP/CIDR filtering
- Interface matching
- Enable/disable without deletion
- Rule ordering (drag-and-drop)
- Advanced: Destination IP, action (accept/drop/reject), rate limiting, connection limiting

### Not Implemented (Intentional)
- **ICMP type filtering:** 99% of users don't understand 20+ ICMP types; ICMPv6 filtering is dangerous
- **Per-rule logging:** Floods kernel logs; requires terminal access; not GUI-friendly
- **Source port matching:** <1% use case
- **TCP flags matching:** Too advanced for target audience
- **MAC filtering:** LAN-only, easily spoofed
- **Time-based rules:** Complex UI, better handled by cron

### Deferred
- **NAT/Port forwarding:** Different scope; would be separate major feature
- **Custom expressions:** Security risk; defeats GUI purpose

---

## 12. Development Workflow

### Pre-Commit Checklist
```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release
```

### Before Architectural Changes
- Read official documentation for the specific version in use
- Verify current code is actually wrong (not just "different from examples")
- Confirm the change solves a real problem
- Test that current code compiles and runs

### Code Review Questions
- Does this make code simpler or more complex?
- Are the abstractions actually needed, or premature?
- Have I tested with realistic data (100+ items)?
- Is this maintainable by someone unfamiliar with the codebase?
- Have I updated relevant documentation (`CLAUDE.md`, `STYLE.md`)?

---

## 13. Common Pitfalls

### Dead Code
Functions marked `#[allow(dead_code)]` must be:
- **Removed** if truly unused with no plans
- **Documented as public API** with examples if intended for library users
- **Marked with TODO** if planned for future feature with issue reference

### Magic Numbers
Use named constants:

```rust
// ❌ Unclear
let shadow = Color::from_rgba(0.0, 0.0, 0.0, 0.35);

// ✅ Self-documenting
const SHADOW_LIGHT_ALPHA: f32 = 0.35;
let shadow = Color::from_rgba(0.0, 0.0, 0.0, SHADOW_LIGHT_ALPHA);
```

### Complex Conditionals
Extract into named functions:

```rust
// ❌ Nested conditionals (5+ levels)
if let Some(src) = source {
    if self.protocol == Protocol::Icmp {
        if src.is_ipv6() {
            errors.source = Some("ICMP (v4) with IPv6 source".into());
        }
    }
}

// ✅ Extracted validation
fn validate_source(&self, errors: &mut FormErrors) -> Option<IpNetwork> {
    // Single-purpose validation logic
}
```

### Premature Abstraction
Wait for 3+ identical use cases before creating helpers. Inline code is often clearer than poorly-abstracted helpers.

### The Unwrap Trap in UI Message Handlers (2026-01-02)

**Pattern to Avoid:**
```rust
fn handle_message(&mut self) -> Task<Message> {
    if let Some(data) = &self.optional_state {
        // ... validation ...
    }

    // DANGER: State could theoretically desync between check and use
    let data = self.optional_state.take().unwrap();  // ❌ Can panic
}
```

**Safe Pattern:**
```rust
fn handle_message(&mut self) -> Task<Message> {
    let Some(data) = self.optional_state.take() else {
        tracing::error!("Message handler called with invalid state");
        return Task::none();
    };
    // ... use data ...
}
```

**Why:** UI frameworks can have subtle state desync bugs. Graceful degradation is better than panics.

**When unwrap() is acceptable:**
- In test code
- After explicit checks where desync is impossible (e.g., `vec[0]` after checking `.len() > 0` in same scope)
- Static initialization where failure is unrecoverable

---

## Appendix: File Permission Reference

**Unix file modes:**
- `0o600` - User read/write (configs, audit logs, profiles)
- `0o700` - User read/write/execute (directories)

**Required locations:**
- Audit log: `~/.local/state/drfw/audit.log` (0o600)
- Config: `~/.config/drfw/config.json` (0o600)
- Profiles: `~/.local/share/drfw/profiles/*.json` (0o600)
- Snapshots: `~/.local/state/drfw/snapshots/*.json` (0o600)

**Windows:** Document that users should configure ACLs on data directories (`%LOCALAPPDATA%\drfw\drfw\data`).

---

**Last Updated:** 2026-01-02 (Post-implementation review - added DRY, file size guidelines, unwrap safety, TODO hygiene)
**DRFW Version:** 0.1.0
**Iced Version:** 0.14
