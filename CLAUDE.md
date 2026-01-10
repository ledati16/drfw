# DRFW Development Standards

**Purpose:** Core development guidelines for LLM agents and contributors working on DRFW.

**Principles:** Security-first, performance-conscious, test-driven, maintainable code.

---

## 1. Code Quality

### Linting & Static Analysis
- **Strict compliance:** Clippy pedantic lints enabled in `Cargo.toml`
- **Centralized config:** All lint allows are in `[lints.clippy]` section with documented rationale
- **No scattered suppressions:** Avoid per-function `#[allow(...)]` unless truly function-specific
- **Refactor over suppress:** Fix warnings through better design, not suppression

### Documentation Standards
- **Public APIs:** All public functions require doc comments with:
  - Purpose and behavior
  - Arguments and return values
  - Error conditions
  - Example usage for non-trivial cases
- **Complex logic:** Document **why**, not what (code shows what)
- **Error semantics:** Functions that can fail must document all failure modes
- **Technical terms:** Use backticks for identifiers (`nft`, `pkexec`, `DRFW_NFT_COMMAND`)

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
- **Patterns that look similar but aren't:** Before extracting, verify the code paths
  are actually identical. Example: Four "secure file write" locations appeared similar
  but used different modes (append vs truncate) and APIs (sync vs async)—only 2 were
  actually the same pattern. Extraction would have been wrong.

**Real-world example: Button styling consolidation**
```rust
// ❌ BEFORE: 8 functions × ~70 lines = 560 lines of duplication
pub fn primary_button(theme, status) -> Style {
    let base = Style { background: theme.accent, ... };
    match status {
        Hovered => Style { background: brighten(theme.accent), ... },
        Pressed => Style { background: darken(theme.accent), ... },
        // ... repeated for all states
    }
}
// ... 7 more nearly-identical functions

// ✅ AFTER: Configuration-driven with shared builder
struct ButtonStyleConfig {
    base_color: ButtonColorSource,
    hover_brightness: f32,
    // ... config fields
}

impl ButtonStyleConfig {
    const PRIMARY: Self = Self { base_color: Accent, hover_brightness: 1.08, ... };
    const DANGER: Self = Self { base_color: Danger, hover_brightness: 1.08, ... };
    // ... 6 more const configs
}

pub fn primary_button(theme, status) -> Style {
    build_button_style(theme, status, ButtonStyleConfig::PRIMARY)  // 1 line
}
```
Result: 8 functions reduced to single-line delegations, unified logic in `build_button_style()`.

**Real-world example: Audit logging consolidation**
```rust
// ❌ BEFORE: 20 functions × ~20 lines each = 400+ lines of duplication
pub async fn log_apply(enable_event_log: bool, rule_count: usize, ...) {
    if !enable_event_log { return; }
    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(EventType::ApplyRules, success, json!({...}), error);
        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}
// ... 19 more nearly-identical functions

// ✅ AFTER: Internal helper + single-line delegations
async fn log_event_internal(
    enable_event_log: bool, event_type: EventType, success: bool,
    details: serde_json::Value, error: Option<String>,
) {
    if !enable_event_log { return; }
    if let Ok(audit) = AuditLog::new() {
        let event = AuditEvent::new(event_type, success, details, error);
        if let Err(e) = audit.log(event).await {
            tracing::warn!("Failed to write audit log: {}", e);
        }
    }
}

pub async fn log_apply(enable_event_log: bool, rule_count: usize, ...) {
    log_event_internal(enable_event_log, EventType::ApplyRules, success,
        json!({ "rule_count": rule_count, "enabled_count": enabled_count }), error).await;
}
```
Result: `audit.rs` reduced from 782 → 481 lines (38% reduction), 20 functions now single-line delegations.

### File Size Guidelines

- **Single file limit:** ~3000-4000 lines before considering a split
- **When to split:** Consider submodules when a file exceeds 3000 lines with clear logical sections
- **Module structure:** Group related functionality (`view/rules.rs`, `view/settings.rs`, `view/modals.rs`)
- **Trade-off:** Balance between too many small files vs monolithic files

**Example:** `app/view.rs` was split into `app/view/` module (~5000 lines across 15 files). `app/mod.rs` was split by extracting handlers into `app/handlers/` (~1100 lines remaining in mod.rs).

**Note:** This is a soft guideline, not a hard rule. Prioritize logical cohesion over arbitrary line counts.

### Refactoring Large Files

When splitting monolithic files into modules:

**Domain Separation:**
```rust
// ✅ Group by domain responsibility
handlers/
  rules.rs      // Rule CRUD, form handling, drag-drop
  apply.rs      // Apply/verify/revert workflow
  profiles.rs   // Profile management
  settings.rs   // Configuration changes
  ui_state.rs   // Modal state, undo/redo, keyboard
  export.rs     // Export and audit operations
```

**Avoid Redundant Operations:**
```rust
// ❌ BAD: Calling internal implementation twice
state.mark_profile_dirty();  // Calls update_cached_text() internally
state.update_cached_text();  // Redundant second call

// ✅ GOOD: Let mark_profile_dirty handle cache updates
state.mark_profile_dirty();
```

**Check method internals** before calling multiple state-changing methods in sequence.

**Handler Organization:**
- **Module docs:** Explain domain scope at top of file
- **Logical grouping:** Related handlers together (create/edit/delete for same entity)
- **Tests at bottom:** Keep handler tests in same file for discoverability
- **Pure helpers:** Extract to `helpers/` if no state mutation

**Refactoring Checklist:**
1. Read original file completely before splitting
2. Verify all methods accounted for (count functions before/after)
3. **Line-by-line verification of inline handlers:**
   ```bash
   # For EVERY inline handler in update():
   git show COMMIT:path/to/file.rs | grep "Message::HandlerName" -A 10 > /tmp/original
   # Compare with extracted handler:
   diff -u /tmp/original new/handlers/file.rs
   ```
4. Check for internal method calls that might be duplicated
5. Run `cargo test` and `cargo clippy` after each phase
6. **Functional testing:** Test affected UI features (search, filters, modals)
7. Add unit tests for extracted handlers

**Critical:** Counting functions ≠ verifying logic. Must diff multi-statement inline handlers line-by-line.

**Example:** `app/mod.rs` refactor (2026-01-04) split 2,940 lines into 8 handler modules. Initial review found all 38 methods but missed 4 logic bugs in inline handlers (font search, tag filter, form cancel, drag state) due to pattern-matching instead of line-by-line verification. Bugs caught by functional testing, fixed in commit 945ba6d.

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
- **Consistent format:** Use `NftablesErrorPattern::match_error()` to translate raw error strings at display time

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
- **Verify before apply:** Run `nft --check` to validate syntax before applying rules
- **Timeout protection:** 2-minute default maximum
- **Error translation:** Map exit codes to user actions (126=cancelled, 127=auth failed)
- **Audit logging:** Log all privileged operations with timestamps
- **Test bypass:** `DRFW_NFT_COMMAND=tests/mock_nft.sh` for tests with mock nft

### Subprocess Timeout Pattern
**All subprocess calls should have timeouts** to prevent indefinite hangs:

```rust
// ✅ Async with timeout
match tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await {
    Ok(Ok(output)) => process_output(output),
    Ok(Err(e)) => handle_io_error(e),
    Err(_) => handle_timeout(),
}

// ✅ Sync subprocess (for non-async contexts)
use std::process::Command;
let output = Command::new("pgrep")
    .args(["-a", "polkit"])
    .output()  // Note: no built-in timeout in std::process
    .map_err(|e| /* handle error */)?;
```

**Note:** `std::process::Command` has no built-in timeout. For sync calls that could hang (e.g., network operations, user prompts), consider:
1. Using `tokio::process::Command` with `tokio::time::timeout`
2. Spawning in a separate thread with a timeout mechanism
3. Documenting the potential hang in function docs

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
- **Environment safety:** Never touch real user data; use temp dirs and `DRFW_NFT_COMMAND` for mock

### Test File Organization

| File | Purpose | Authoritative For |
|------|---------|-------------------|
| `src/core/tests.rs` | Unit tests for firewall JSON generation, property tests, verification tests | JSON output structure, rule ordering, protocol handling |
| `src/core/nft_json.rs` | Module tests for snapshot and checksum functions | Snapshot validation, checksums, emergency ruleset |
| `tests/integration_tests.rs` | End-to-end tests with mock nft, CLI operations, profiles | Verification flow, CLI exports, profile operations |
| `src/core/test_helpers.rs` | Shared test utilities (Rule/Ruleset creation) | - |
| `src/app/handlers/test_utils.rs` | App State creation for handler tests | - |
| `tools/stress_gen.rs` | Stress test profile generator (feature-gated) | Coverage testing, edge cases |

**Key principle:** Each test concept should exist in exactly ONE location. The "authoritative" location is closest to the implementation being tested.

### Test Helper Modules

Use the shared test helpers to avoid duplication:

```rust
// For core tests (firewall rules, rulesets)
use crate::core::test_helpers::{create_test_ruleset, create_test_rule, create_full_test_rule};

// For app handler tests (app state)
use crate::app::handlers::test_utils::create_test_state;

// For tests that use nft operations (most common case)
use crate::core::test_helpers::setup_mock_nft;

// For tests that need exclusive env var access (e.g., testing different elevation methods)
use crate::core::test_helpers::ENV_VAR_MUTEX;
```

### Environment Variables

| Variable | Purpose | When to Use |
|----------|---------|-------------|
| `DRFW_NFT_COMMAND` | Path to nft binary or mock script (skips elevation) | All tests that use nft operations |
| `DRFW_TEST_DATA_DIR` | Overrides data directory (`~/.local/share/drfw/`) | Tests that access profiles |
| `DRFW_TEST_STATE_DIR` | Overrides state directory (`~/.local/state/drfw/`) | Tests that access audit logs/snapshots |

### Async vs Sync Tests

**Use `#[tokio::test]` only when:**
- The test actually calls `async` functions that need `.await`
- Testing async workflows (verify_ruleset, apply, profile I/O)

**Use `#[test]` for:**
- Pure data transformation (JSON generation, serialization)
- Synchronous validation
- Cache rebuilding tests

```rust
// ❌ Unnecessary async - no await needed
#[tokio::test]
async fn test_json_output() {
    let ruleset = create_test_ruleset();
    let json = ruleset.to_nftables_json();  // Not async
    assert!(json["nftables"].is_array());
}

// ✅ Correct - synchronous test
#[test]
fn test_json_output() {
    let ruleset = create_test_ruleset();
    let json = ruleset.to_nftables_json();
    assert!(json["nftables"].is_array());
}
```

### Test Patterns
```rust
#[test]
fn test_validator() {
    assert_eq!(sanitize_label("Valid_Name-123"), "Valid_Name-123");
    assert_eq!(sanitize_label("Bad$Chars"), "BadChars");
    assert_eq!(sanitize_label(&"x".repeat(100)).len(), 64);
}

#[tokio::test]
async fn test_nft_operation() {
    use crate::core::test_helpers::setup_mock_nft;

    // One-time setup, safe to call before any .await
    // Sets DRFW_NFT_COMMAND to use the mock script
    setup_mock_nft();

    let result = verify_ruleset(json).await;
    assert!(result.is_ok());
}
```

### CI/CD Compatibility
- All tests use mock nft and require no privileges
- Tests should never touch real nftables or require elevation
- Document any special requirements in module-level docs

### Running Tests

```bash
# Standard test run - uses mock nft, no privileges needed
cargo test

# Explicit mock path (equivalent to above, tests set this automatically)
DRFW_NFT_COMMAND=tests/mock_nft.sh cargo test
```

**Note:** All tests automatically use the mock nft script via `setup_mock_nft()`.
Tests never require root privileges or touch real nftables.

### Stress Test Generator

The `stress_gen` tool generates profiles with comprehensive rule variations for testing:

```bash
# Generate 100 rules with good coverage
cargo run --bin stress_gen --features stress_gen -- -o profiles/stress-test.json

# Generate 500 rules with edge cases (boundary values, special chars)
cargo run --bin stress_gen --features stress_gen -- --count 500 --edge-cases -o profiles/edge-cases.json

# Reproducible generation (for bug reports)
cargo run --bin stress_gen --features stress_gen -- --count 200 --seed 12345 -o /tmp/repro.json

# Generate and verify with nft --check
cargo run --bin stress_gen --features stress_gen -- --count 100 --verify -o /tmp/verified.json

# Predefined scenarios: minimal (10), typical (50), enterprise (200), chaos (1000)
cargo run --bin stress_gen --features stress_gen -- --scenario chaos -o /tmp/chaos.json
```

**Coverage guarantees:** The generator ensures all protocol types, actions, chains, reject types, and rate limit time units are represented. Use `--report` to see distribution.

### TODO Comment Hygiene

- **Mark phase/completion:** `TODO (Phase 6): Wire up to diagnostics viewer`
- **Update or remove:** Review all TODOs after completing phases
- **Track separately:** Consider using GitHub Issues for long-term TODOs instead of code comments
- **Outdated TODOs:** When features are implemented differently than planned, update or remove the TODO rather than leaving stale comments

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
- Display strings for frequently-rendered data (see example below)

**Example: Caching formatted display strings**
```rust
// In your data struct (e.g., Rule)
pub struct Rule {
    pub action: Action,
    pub rate_limit: Option<RateLimit>,
    // ... other fields ...

    // Cached display strings (Phase 2.3 optimization)
    #[serde(skip)]
    pub action_display: String,  // Pre-formatted "D (5/s)" or "A"

    #[serde(skip)]
    pub interface_display: String,  // Pre-formatted "@eth0" or "Any"
}

// Populate in rebuild_caches() (called once per data change)
pub fn rebuild_caches(&mut self) {
    self.action_display = if let Some(ref rate_limit) = self.rate_limit_display {
        format!("{} ({})", self.action.as_char(), rate_limit)
    } else {
        self.action.as_char().to_string()
    };

    self.interface_display = if let Some(ref iface) = self.interface {
        format!("@{}", iface)
    } else {
        "Any".to_string()
    };
}

// In view() - zero allocations per frame
pub fn view(&self) -> Element {
    text(&rule.action_display)  // ✅ Use cached string
    // NOT: text(format!("{}", rule.action))  // ❌ Allocates every frame
}
```

**Pre-allocate collections:**
```rust
let mut cards = Vec::with_capacity(filtered_rules.len());
let mut output = String::with_capacity(estimated_size);
```

**Avoid allocations:**
```rust
// ❌ Allocates every frame
let text = format!("{}-{}", start, end);

// ✅ Cache as struct field (best for repeated rendering)
self.cached_range = format!("{}-{}", start, end);  // Once in update()
text(&self.cached_range)  // Reference in view()

// ✅ Stack buffer (for one-time use)
let mut buf = String::with_capacity(12);
write!(&mut buf, "{}-{}", start, end).ok();

// ✅ Static reference (for simple conversions)
"Any".into()  // Not "Any".to_string()
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

### Stress Test Results (2025-01-07)

The architecture has been validated with **700 rules** (varied protocols, ports, sources, destinations, tags):

| Metric | Result |
|--------|--------|
| UI scrolling | Smooth, no lag |
| Search/filter | Instant response |
| Memory usage | No measurable increase |
| Apply to kernel | Works correctly |
| Save to System | Works correctly |

**Key insight:** Widget allocation for 700 rule cards completes in milliseconds. The pre-tokenization caching (`cached_nft_tokens`) and `keyed_column` widget reconciliation handle large rulesets efficiently. **Virtual scrolling (`sensor` widget) is not needed** - it would add complexity and cause layout jumping due to variable card heights.

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
1. **Syntax check:** `nft --json --check -f -` (requires elevation)
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

All logging functions delegate to an internal helper (see DRY section for details):

```rust
// Internal helper handles: enable check, AuditLog creation, error warning
async fn log_event_internal(enable_event_log: bool, event_type: EventType, ...) { ... }

// Public functions are single-line delegations
pub async fn log_apply(enable_event_log: bool, rule_count: usize, ...) {
    log_event_internal(enable_event_log, EventType::ApplyRules, success,
        json!({ "rule_count": rule_count, "enabled_count": enabled_count }), error).await;
}
```

---

## 11. Firewall Features

### Implemented
- Protocol filtering (TCP, UDP, ICMP, ICMPv6, Any)
- Port filtering (single or range)
- Source IP/CIDR filtering
- Interface matching (input/output)
- Enable/disable without deletion
- Rule ordering (drag-and-drop)
- Per-rule logging (with configurable prefix)
- Advanced: Destination IP, action (accept/drop/reject), rate limiting, connection limiting

### Not Implemented (Intentional)
- **ICMP type filtering:** 99% of users don't understand 20+ ICMP types; ICMPv6 filtering is dangerous
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
cargo clippy --all-targets  # pedantic lints configured in Cargo.toml
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

**Last Updated:** 2026-01-09 (Added stress_gen docs, enabled pedantic lints in Cargo.toml, updated feature list)
**DRFW Version:** 0.9.0
**Iced Version:** 0.14
