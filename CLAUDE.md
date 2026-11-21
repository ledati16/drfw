# DRFW Development Standards

**Purpose:** Core development guidelines for LLM agents and contributors working on DRFW.

**Principles:** Security-first, performance-conscious, test-driven, maintainable code.

---

## 1. Code Quality

### Linting & Static Analysis
- **Strict compliance:** Clippy pedantic lints enabled in `Cargo.toml`
- **Centralized config:** All lint allows are in `[lints.clippy]` section with documented rationale; no crate-level `#![allow(...)]` in `lib.rs`, `main.rs` or `tests/*.rs`
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

### Rule Validation (single source of truth)
`src/core/validate.rs` decides what a valid rule/ruleset is: `Rule::validate()`,
`AdvancedSecuritySettings::validate()`, `FirewallRuleset::validate()` (full report) and
`FirewallRuleset::validate_for_apply()` (only what blocks applying).

- **The form delegates:** `RuleForm::validate` builds the candidate `Rule` and calls
  `Rule::validate`; it only adds text-input errors (unparseable numbers, rate limit
  enabled without a rate). Never add a rule check to the form alone.
- **Loading never drops data:** invalid rules stay in the profile and are flagged in the
  sidebar (cached in `update_cached_text()`); duplicate ids are regenerated and labels/tags
  sanitized by `FirewallRuleset::normalize_loaded()`.
- **Applying is refused** while an applied rule (enabled; OUTPUT rules only in Server
  Mode) is invalid or a ruleset-level issue exists. Every path that sends a ruleset to the
  kernel or the system config must call `validate_for_apply()` first.

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

Use `utils::write_atomic_private[_async]()` (unique temp file, 0600, sync, rename) rather
than a fixed `*.tmp` name: two overlapping saves must never share a temp file.

**Required for:** Config files, profiles, and any file replaced wholesale (clearing the
audit log). Appends to the audit log are single `write`s instead (see §10).

**Never replace user data silently:**
- Creating or renaming a profile never overwrites an existing one (names compared
  case-insensitively; `persist_noclobber`, `renameat2(RENAME_NOREPLACE)` or link+unlink).
- A profile or `config.json` that exists but can't be read (corrupt, newer `version`, too
  large) is copied to `<file>.corrupt-<UTC timestamp>` (0600) before any fallback. The GUI
  opens such a profile read-only (no edits, no autosave) until the user switches profile or
  chooses "Start fresh"; a missing file is the normal default path.
- Profiles carry `"version"` (`PROFILE_FORMAT_VERSION`, files without it are version 1);
  bump it when older builds would misread new files.
- There are no profile checksums (the old `.sha256` files are removed on save/startup): a
  checksum next to the data protects nothing.

**Windows note:** Document ACL requirements since Unix permissions don't apply

---

## 4. Privilege Escalation

### What Runs Elevated
Only three things, all in `src/elevation.rs`:

1. **`nft --json --check -f -`**: the authoritative verify, used only when the
   unprivileged check (`unshare -rn nft --check`, private user + network namespace)
   does not pass. Only a *pass* in the namespace is trusted.
2. **`/bin/sh` + `APPLY_SCRIPT`**: apply and arm the revert guard (one prompt per apply).
3. **`/bin/sh` + `SAVE_CONFIG_SCRIPT`**: Save to System, optionally followed by
   `systemctl enable <SYSTEM_NFT_SERVICE>` in the same script (one prompt either way).

Elevated `nft` is `distro::NFT_COMMAND`: the packager's `DRFW_NFT_PATH`, else plain
`nft`. Unprivileged `systemctl is-enabled`/`is-active` queries (`core::boot`) never
elevate.

The scripts are compile-time constants. Data reaches them only as argv (checked
against an allowlist inside the script) and stdin; nothing is ever interpolated into
script text. Exit codes are structured, and 126/127 are never used by the scripts:
callers read those as authentication failures of the elevation tool.

### Elevation Strategy
Chosen in `build_elevated_command()`, from the `ElevationContext` the front end sets
once at startup (`elevation::set_context`: `Gui` in `run_gui()`, `Cli` in `main()`):

1. **Already root:** run directly (no prompt)
2. **`DRFW_ELEVATION_METHOD`** (`sudo`/`run0`/`pkexec`): forced method (which tool
   asks; there is no password-less mode)
3. **GUI:** always `pkexec`, even when started from a terminal (`run0`/`sudo` would
   prompt invisibly in that terminal); no `pkexec` → `PkexecNotFound`
4. **CLI (or no context set):** stdin is a TTY → `run0` (systemd v256+, no SUID),
   else `sudo`; no TTY → `pkexec`

Every elevated child uses `kill_on_drop(true)`. DRFW ships **no polkit rule**: every
elevated operation asks once. Caching `/bin/sh` would allow arbitrary root commands;
caching `nft` makes root `nft` (a file-read primitive: `nft -c -f <file>` echoes lines
in errors) available to anything that can drive the DRFW process, only to save a
prompt in the rare elevated-check fallback. Never suggest sudoers `NOPASSWD` for
unattended applies: the elevated program is `/bin/sh`, so that is full root.

### Root-Side Revert Guard (dead-man switch)
`core/apply_guard.rs` + `APPLY_SCRIPT`/`WATCHER_SCRIPT`. As root, in one elevation:

0. `trap '' HUP INT QUIT TERM PIPE` (an SSH drop or Ctrl-C after the password must not
   stop the script halfway), then print `drfw-apply-started` (DRFW now knows the
   script runs as root: a later timeout or signal means "state unknown", not
   "nothing changed"). Take the `flock` on `/run/drfw/lock`.
1. Save the current `inet drfw` table (stdout of `nft list table` only) or the fact
   that there is none as an atomic revert batch in root-owned `/run/drfw`
   (`GUARD_STATE_DIR`). If an earlier guard is still pending, inherit its revert file:
   a timeout returns to the last *confirmed* state.
2. Start the detached watcher (`systemd-run` when systemd is PID 1, else `setsid`)
   **before** anything changes; if it can't start, nothing changed (exit 4).
3. Apply the new JSON (`nft --json -f -`). On rejection write the new guard's status
   `not-applied` (its watcher exits without reverting); nothing changed (exit 3).
4. Supersede the earlier guard, create `armed-<nonce>` (only now does the watcher
   accept tokens) and record the guard in `active`. If `armed` cannot be created the
   rules revert at the deadline and cannot be confirmed (exit 5, "state unknown").

Even a `SIGKILL` between 3 and 4 leaves a guard: at the deadline the watcher takes the
lock (waits for a still-running apply), and reverts if there is no status, armed or not
(the revert file is the pre-apply state, so restoring it is right either way). DRFW maps
a signal or an unexpected exit after the start marker, and a script that outlives
`SCRIPT_TIMEOUT` (90 s, after authentication; root, so `kill_on_drop` can't stop it), to
`ApplyError::StateUnknown` (`rules_may_be_active()`; exit 6 in the CLI). The GUI shows
the persistent, short `STATE_UNKNOWN_BANNER` (≤ 120 chars, "MAY BE ACTIVE" first; banners
truncate) and puts the full reason in the "Apply Details" panel
(`VerifyErrorsPanel::apply_state_unknown`). Before the marker every failure means nothing
changed.

The watcher polls once per second on `/proc/uptime` (immune to clock changes), and
checks the deadline **before** touching the user's directory. The user side confirms or
reverts by creating `drfw-confirm-<nonce>` / `drfw-revert-<nonce>` token files in its
own runtime dir (no privileges). Trust boundary: the nonce is **not** secret (it is in
`ps`, the unit name and world-readable `/run/drfw/active`); ownership is the check.
DRFW only uses a token dir owned by the user with mode 0700 or stricter
(`XDG_RUNTIME_DIR`, else the state dir, else it refuses before elevating), and the
watcher only counts tokens owned by that uid (`find -maxdepth 1 -name … -user <uid>`,
wrapped in `timeout 2`). It only lists that dir, never follows or writes into it, and
writes the outcome to world-readable `/run/drfw/status-<nonce>`. `/run/drfw/active`
names the pending guard (`drfw status` reads it). Revert falls back to deleting the drfw
table, never to re-applying drop policies. Closing the GUI, a crash, a closed terminal
or a dropped SSH session all end in the revert. A revert whose lock is still held after
60 s (once armed) goes ahead anyway and logs it (journal, or `logger -t drfw`).

### Kept-Ruleset Record (`core::confirmed`)
One record of the last ruleset **applied and kept**, shared by the GUI and the CLI:
`<state dir>/confirmed-ruleset.json` (0600, atomic). It holds the exact nftables JSON
text nft read on stdin, the ruleset (profile format, read back with `parse_profile`) and
the boot id (`/proc/sys/kernel/random/boot_id`).

- **Writers (only these two):** `apply_guarded` after an unguarded apply (GUI with
  auto-revert off, `drfw apply --no-confirm`: kind `unguarded`) and
  `GuardHandle::wait_outcome` on a confirmation (kind `confirmed`). Reverted, superseded
  and failed applies never write it. The GUI keeps the same record in
  `State::confirmed_record` (loaded at startup, replaced when an apply is kept).
- **"Tested" = the same JSON bytes:** `ConfirmedRecord::matches(json)`, used by the Save
  to System dialog (`SaveTested`) and `drfw save`. Do not compare rulesets field by field
  for this.
- **Not live state:** a reboot, `nft flush` or another tool invalidates it.
  `from_this_boot()` is false for an earlier boot or an unknown boot id; user-facing text
  must then say "kept in an earlier session", never "running now".
- Older DRFW wrote the bare nftables JSON: still read (confirmed, no ruleset, boot unknown).
- `--no-confirm` records on purpose: the same explicit choice as auto-revert off in the
  GUI, and a stale record would describe rules that are no longer in place.

### Retention Guard (`core::retention`)
Before Apply and Save to System (GUI and CLI), `RetentionWarning::check(kept, next)`
compares with the record's ruleset (DRFW's defaults when there is none): at least 3
**and** at least 40 % of its enabled rules removed (matched by id; disabled = removed),
Desktop→Server, or block forwarding turned on. GUI: computed in `update()`
(`ApplySession::retention`, `SaveToSystemDialog::retention`); only the "Apply anyway"
button (`Message::ProceedToApplyAnyway`) proceeds, Enter (`ProceedToApply`) is refused,
and `SaveToSystemDialog::primary_source()` never picks the editor's rules then. CLI
(`retention_guard` in `main.rs`): prints the same `lines`, asks y/N on a terminal,
otherwise needs `--yes` (exit code 9, nothing changed).

**Never** move the revert back into the DRFW process or require a second prompt for it:
that fails exactly when the user is locked out. **Never** start the watcher after the
apply again: that reopens the window in which live rules have no guard.

### Save to System
`SAVE_CONFIG_SCRIPT` (argv: target = `drfw::SYSTEM_NFT_PATH`, nft = `NFT_COMMAND`,
optional service = `drfw::SYSTEM_NFT_SERVICE`; all validated in the script first):
create the target's directory if missing, write stdin to a temp file next to the
target, `nft -c -f` **that exact file**, copy the old target to `.drfw-bak` (and, once,
to `.drfw-orig`, never overwritten), sync, then rename into place. Any failure up to
here leaves the target untouched. Then, only if a service was passed, `systemctl enable`
it (**never** `start`: that reloads rules mid-session); a failure there is reported as
`enable=failed: ...` on stdout with exit 0, because the file was saved. `systemctl` is
called by name, through the `PATH` the elevation tool gives root (pkexec, sudo's
`secure_path`, run0); `APPLY_SCRIPT` already relies on that for `systemctl`/`systemd-run`.

The script ignores `HUP`/`INT`/`QUIT`/`TERM`/`PIPE` like `APPLY_SCRIPT`.

`drfw save <profile> [--enable-at-boot] [--yes]` is the same path for headless
servers (`validate_for_apply`, unprivileged check, `write_config_file_and_enable`). A
profile whose JSON is not the kept-ruleset record (see above) prints a loud
"not the one last applied and confirmed; no dead-man switch at boot" warning and needs
`--yes` (no TTY) or a y/N answer (exit 7 otherwise); the retention guard follows (exit 9). With `--enable-at-boot` a failed enable exits 8; without
it a disabled boot service is warned about. Tests set `DRFW_TEST_SYSTEM_NFT_PATH`
(honoured only together with `DRFW_NFT_COMMAND`).

The dialog asks `core::boot::query_boot_status()` (unprivileged) when it opens, shows
the result and an "Also enable at boot" checkbox (checked when the unit is disabled);
the result banner re-queries after saving. Both are prepared in `update()`
(`SaveToSystemDialog`), never in `view()`. An enabled `drfw.service` counts too: the
unit generated by `drfw print-service-unit` loads the same file.

### Compile-Time Distro Configuration
`src/distro.rs`: `SYSTEM_NFT_PATH` (`DRFW_SYSTEM_NFT_PATH`), `SYSTEM_NFT_SERVICE`
(`DRFW_SYSTEM_NFT_SERVICE`), `NFT_PATH` (`DRFW_NFT_PATH`, optional), re-exported as
`drfw::SYSTEM_NFT_PATH`/`SYSTEM_NFT_SERVICE`. `const _: () = assert!(...)` checks them
with the const fns `is_valid_absolute_path` (same `[A-Za-z0-9/._@+-]` allowlist as the
scripts' `safe_path`) and `is_valid_service_name`, so a bad value fails the build.
`build.rs` has `rerun-if-env-changed` for all three. `contrib/drfw.service.in` is the
unit template; `drfw print-service-unit` (hidden) fills it with these values, and the
PKGBUILD installs that output. Never hard-code `/etc/nftables.conf` or `nft` paths
elsewhere; tests must compare against the constants (packagers build with overrides).

### Security Requirements
- **Validate, then verify, then apply:** `validate_for_apply()` → `nft --check` → apply
- **Timeout protection:** 2-minute maximum for anything that can show an auth dialog
- **Error translation:** Map exit codes to user actions (126=cancelled, 127=auth failed)
- **Audit logging:** Log all privileged operations with timestamps
- **Test bypass:** `DRFW_NFT_COMMAND=tests/mock_nft.sh` for tests with mock nft (no elevation)

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

### Crate Layout

All code lives in the library crate (`src/lib.rs`), including the GUI (private
`app` module, started by the public `drfw::run_gui()`) and the version strings
(`drfw::build_info`). `src/main.rs` is only the CLI front end (clap `Cli`, the
`list`/`apply`/`status`/`check`/`export` commands, the countdown) and uses the
library through its public API (`drfw::…`). Never re-declare library modules
with `mod` in `main.rs`: that compiles them twice, as two incompatible copies,
and runs their unit tests twice. Inside the library, always write `crate::…`;
`drfw::…` belongs in `main.rs`, `tests/`, `tools/` and doctests.

Unit tests therefore run exactly once: in the lib test target, except the CLI
tests in `src/main.rs`, which run in the bin test target.

### Test File Organization

| File | Purpose | Authoritative For |
|------|---------|-------------------|
| `src/core/tests.rs` | Unit tests for JSON generation, property tests, JSON format details | JSON output structure, rule ordering, protocol handling, IP format compliance, per-source set shape, command origins (every command of a user rule carries its id) |
| `src/core/verify.rs` | Unit tests for the verify plumbing | Exit-code verdicts, `VerifyResult` constructors/summary, `locate_errors()` fallback to unmapped errors |
| `src/core/nft_errors.rs` | Unit tests for nft error parsing and attribution | Parsing real nft stderr (located, multi-line, kernel, JSON), excerpts, text line → rule/base rule/chain/header mapping |
| `src/core/nft_text.rs` | Unit tests for the text renderer | Header/idempotent preamble, statement rendering, render errors |
| `src/core/apply_guard.rs` | Unit tests for the guard's user side | Outcome parsing, exit-code mapping, tokens, `pending_guard()` |
| `src/audit.rs` | Unit tests for the audit log | Event (de)serialization, chrono-era timestamps, rotation, clearing |
| `src/app/diagnostics.rs` | Unit tests for the event log view model | Row precompute (local time/date), filter + search cache, in-flight/generation reload logic |
| `src/app/verify_errors.rs` | Unit tests for the "Verification Errors" panel model | Row titles, summary/banner wording, "Edit Rule" only for rules that still exist |
| `src/distro.rs` | Compile-time validators, service unit template | `is_valid_absolute_path()`, `is_valid_service_name()`, `service_unit()` |
| `src/core/boot.rs` | `systemctl` output mapping | `enablement_from_output()`, `BootStatus` summaries and checkbox rules |
| `tests/integration_tests.rs` | End-to-end tests with mock nft, CLI binary, profiles | **Verification flow** (valid/empty/multi-rule), guarded-apply plumbing (incl. a killed apply script → `StateUnknown`, guard still reverts; which applies write the kept-ruleset record), CLI `status`/`check`/`save`/`print-service-unit`, the retention guard of `apply`/`save` and the `--help` exit codes (runs the real binary), save script incl. enable-at-boot (fake `systemctl`), exports, audit logging |
| `tests/real_nft.rs` | Real `nft` in `unshare -rn` (own binary) | Text output loads, JSON and text give identical kernel rulesets (proptest), idempotent reload, no widening, per-source sets (replaced on apply, clients kept apart), Server-mode loopback, a user Drop rule blocks ping (two netns), interface length limit vs nft, Save to System script, revert guard end to end (incl. SIGHUP/INT/TERM/KILL right after the rules went live, tokens of other uids ignored) |
| `src/core/evaluate.rs` | Unit tests for the rule evaluator | Chain model (order, family copies, skipped rules), limits/conditions as `Limited`, reachability sets (subtracted drops, `AllExcept`, conditional access, caveats), base rule names match the generator |
| `src/core/addr_set.rs` | Unit tests for the address-set arithmetic | Union/intersection/difference/complement, CIDR decomposition |
| `src/core/exposure.rs` | Unit tests for socket discovery | `/proc/net` parsing (IPv4, IPv6, v4-mapped, UDP), inode → process mapping on a fixture tree, dual-stack heuristic, exposure rows |
| `src/app/exposure.rs` | Unit tests for the Exposure panel model | Row order and badges, editor vs applied answers, scan errors |
| `tests/evaluate.rs` | Evaluator property tests; kernel agreement in two `unshare -rn` namespaces over veth (own binary re-executed as server/client helpers) | Per-source verdicts agree with the reachability sets (proptest); **the evaluator agrees with real nft** on random rulesets and probes (proptest) and directed cases |
| `tests/verify_errors.rs` | Error attribution against real `nft` in `unshare -rn`, and `drfw check` output (own binary) | A rejected ruleset names the rule that caused each error (also with per-source sets), CLI prints mapped errors without color codes |
| `tests/profile_storage.rs` | Profile/config files on disk (own binary; tests serialized because they set `DRFW_TEST_DATA_DIR`) | Corrupt/newer/oversized profiles, duplicate ids, no-replace create/rename, file modes, config recovery |
| `src/core/validate.rs` | Unit + property tests for the validator | Every rule/ruleset issue type, valid rules always validate |
| `src/main.rs` | CLI unit tests (bin test target) | Countdown key classification and rounding, CLI usage examples parse, exit codes distinct and documented |
| `src/core/test_helpers.rs` | Shared test utilities (Rule/Ruleset creation, mock setup, `CHRONO_TIMESTAMPS`) | - |
| `src/app/handlers/test_utils.rs` | App State creation for handler tests | - |
| `tools/stress_gen.rs` | Stress test profile generator (feature-gated) | Coverage testing, edge cases |

**Key principle:** Each test concept should exist in exactly ONE location. The "authoritative" location is closest to the implementation being tested.

**Verification tests belong in `tests/integration_tests.rs`**, not in `src/core/tests.rs`. The verification flow exercises the mock nft script, making it an integration test. JSON generation tests (which don't invoke nft) belong in `src/core/tests.rs`. Tests of how real nft errors map back to rules belong in `tests/verify_errors.rs`.

### Test Helper Modules

Use the shared test helpers to avoid duplication **within the library crate**:

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

**Note:** Integration tests in `tests/` (like `src/main.rs` and `tools/stress_gen.rs`) are separate crates that link the library and see only its `pub` API; they **cannot access `#[cfg(test)]` modules** from the library. Therefore, `tests/integration_tests.rs` has its own copies of helper functions. This is unavoidable due to Rust's test architecture. When modifying Rule fields, update helpers in both locations.

### Environment Variables

| Variable | Purpose | When to Use |
|----------|---------|-------------|
| `DRFW_NFT_COMMAND` | Path to nft binary or mock script (skips elevation) | All tests that use nft operations |
| `DRFW_TEST_DATA_DIR` | Overrides data directory (`~/.local/share/drfw/`) | Tests that access profiles |
| `DRFW_TEST_STATE_DIR` | Overrides state directory (`~/.local/state/drfw/`) | Tests that access the audit log |
| `DRFW_REQUIRE_REAL_NFT` | `1` makes `tests/real_nft.rs` fail instead of skipping when `unshare -rn nft` is unavailable | CI (set); never in packaging `check()` |

For tests that run the `drfw` binary (`env!("CARGO_BIN_EXE_drfw")`), set these on the
child `Command`, not with `std::env::set_var`: per-child env cannot race other tests.

`systemctl` has no override variable on purpose (an env var that picks the program
root runs would be one more thing to audit). Tests put a fake `systemctl` first on the
**child's** `PATH` instead: `tests/integration_tests.rs` (`FAKE_SYSTEMCTL`) does this
for the save script (`create_elevated_save_config_command(..).env("PATH", ..)`) and
for `drfw status`.

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
- No test needs privileges. Tests use the mock nft, or the real `nft` inside a private
  user + network namespace (`unshare -rn`), never the host's ruleset
- `tests/real_nft.rs` skips itself without `nft`/user namespaces; CI installs nftables,
  allows user namespaces and sets `DRFW_REQUIRE_REAL_NFT=1` so a skip is a failure
- Document any special requirements in module-level docs

### Running Tests

```bash
# Standard test run - mock nft, plus real nft in a namespace when available
cargo test

# As CI runs it: real-nft tests must run, not skip
DRFW_REQUIRE_REAL_NFT=1 cargo test --locked
```

**Note:** Mock-based tests set `DRFW_NFT_COMMAND` themselves (`setup_mock_nft()`; the
mock needs `jq`). Tests never require root privileges or touch the host's nftables.

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

### Handler Test Coverage

App handler tests (`src/app/handlers/*.rs`) intentionally have lower unit test coverage than core modules. Most handlers are thin orchestration code that:

1. Check/update state
2. Spawn async Tasks calling external services (polkit, file dialogs, nft)
3. Return a `Task<Message>`

**What IS tested:**
- Pure helper functions (`truncate_error_message`, `interpret_elevated_command_output`)
- Simple state mutations (form open/close, toggle flags)
- Core business logic in `src/core/` and `src/validators.rs`

**What is NOT unit tested (by design):**
- Handlers that call `pkexec`/`sudo`/`run0` for elevation
- Handlers that open file dialogs (`rfd::AsyncFileDialog`)
- Handlers that spawn Tasks requiring external services

**Rationale:** Adding mocking infrastructure for these handlers would increase maintenance burden without proportional bug-finding value. These code paths are exercised by:
- Integration tests (`tests/integration_tests.rs`)
- Manual GUI testing
- Rust's type system (catches many bugs at compile time)

**Policy:** If bugs appear in untested handlers, add targeted tests. Otherwise, accept current coverage as reasonable for orchestration code.

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
- Filtered/sorted collections (once per data change), e.g. the diagnostics event log:
  rows are formatted once per load, the visible indices once per filter/search change
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

// One-shot, generation-tagged timers (src/app/debounce.rs) are re-armed from
// state at the end of every update(): no polling subscription, so an idle app
// does not rebuild its view 10 times a second. A timer that fires after newer
// edits carries a stale generation and is ignored (or re-armed for the rest).
```

**Honest autosave (profiles, `handlers/profiles.rs`):**
- Clear `profile_dirty` only when the save result is `Ok` and the ruleset didn't change
  meanwhile; a failure shows a banner, keeps the flag and retries after a delay.
- Async results carry `profile_generation` / `switch_request`; drop results for a profile
  that is no longer active.
- Autosave pauses while the "unsaved changes" dialog is open (so Discard discards), during
  a rename, and while the profile is read-only. "Save & Switch" aborts if the save fails.
- On window close (`exit_on_close_request: false`) pending profile/config saves are
  flushed with a bounded wait before exiting.

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

### One Command List, Two Renderers
`FirewallRuleset::build_commands()` produces the single list of nft commands. It is
serialized as JSON (`to_nftables_json()`, what Apply sends) and rendered as an `nft -f`
text file (`to_nft_text()` in `core/nft_text.rs`: preview, diff, `drfw export --format
nft`, Save to System). Never write a second generator: change `build_commands()` and
both outputs follow. `tests/real_nft.rs` checks that both load identical kernel rulesets.

The text file starts with `table inet drfw` / `delete table inet drfw` (idempotent
replace that works on every nft version; `destroy` needs nft >= 1.0.8) and a
`# Generated by DRFW <version>` header (`nft_text::GENERATED_HEADER`, which
`drfw status` uses to recognise our boot config).

### JSON API for Applying
Apply always uses `nft --json -f -`; the text form is only ever written to files and
checked with `nft -c` before use. Never parse `nft list` text output.

### Apply Workflow
1. **Validate:** `validate_for_apply()` (refuses invalid applied rules)
2. **Verify:** `verify_ruleset()`: unprivileged namespace check, elevated `nft --check`
   only if that does not pass. `drfw check` uses `verify_ruleset_unprivileged()` (never
   prompts)
3. **Apply + guard:** `apply_guarded()` (one elevation; see §4)
4. **Confirm or revert:** token file; the root-side watcher reports the outcome

### Rule Ordering
Input chain, in `build_commands()`:
1. Optional RPF drop, loopback (bypass all checks)
2. Invalid packet drops (avoid wasted cycles)
3. Established/related connections (bulk traffic), `DHCPv6` client replies
4. ICMP redirect drops
5. User-defined rules, in profile order
6. ICMP allow rules (with an ICMP rate limit: neighbor discovery, router
   advertisements and MLD queries first, unlimited)
7. Optional drop logging, rate-limited reject, counter, then the default policy

User rules come **before** the ICMP allows so a user Drop/Reject rule ("drop
everything from X") also stops ICMP. Established/related traffic is accepted before any
user rule: standard stateful behaviour, a Drop rule stops new connections only (and not
ICMP errors related to existing ones). Keep this in README ("Default Protection").

A Drop/Reject rule with both a rate and a connection limit becomes **two** rules (same
matches, one limit each, both tagged `UserRule(id)`): statements AND, and `limit`
short-circuits, so one rule would count only over-rate connections.

---

## 10. Audit Logging

### Requirements
- **Format:** JSON Lines (one event per line)
- **Location:** `~/.local/state/drfw/audit.log` (XDG compliant)
- **Permissions:** `0o600` on creation (user read/write only)
- **One write per line:** event + newline in a single `write` (lines can't interleave);
  the reader skips damaged lines instead of stopping
- **No per-keystroke events:** text and slider settings go through `schedule_slider_log()`
- **Contents:** Timestamps, event type, success/failure, error messages
- **Timestamps:** `jiff::Timestamp`, serialized as RFC 3339 UTC
  (`2026-11-20T22:39:15.366180715Z`), the format chrono-based builds wrote: old logs and
  profiles (`Rule.created_at`) load, and older builds read ours. Keep it that way (tests
  use `test_helpers::CHRONO_TIMESTAMPS`). Display in local time only, in the view model
- **Clearing:** "Clear Log" asks first, runs off the UI thread and atomically replaces the
  log with one whose first line is a `log_cleared` event (or removes it when event
  logging is off), together with `audit.log.old`; failures show a banner
- **Reading:** the diagnostics modal re-reads the log only when its size or mtime
  changed, one load at a time, dropping results of superseded loads (generation)
- **Exclude:** Passwords, API keys, private network details

### Events to Log
- Rule applications (success/failure, rule count), verify results, Save to System
- Reverts (with the guard's outcome)
- Log cleared
- Profile operations (create/delete/rename/switch), logged with their **real** outcome
  (from the async result, never optimistically before the operation ran)
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
- Per-source limits: a rate or connection limit can apply per source address
  (IPv6 per /64) through named dynamic sets instead of being shared by all sources.
  **Accept rules only** (`validate.rs`, `PER_SOURCE_ACCEPT_ONLY`; the form hides the
  checkboxes otherwise): a set holds `PER_SOURCE_SET_SIZE` (65535) sources, and once
  it is full new sources are not tracked. For Accept that fails closed (new clients
  fall through to the policy, so a flood from more distinct, e.g. spoofed, addresses
  locks new clients out until it stops); for Drop/Reject it would fail open
- Advanced security: Server Mode (output policy drop), strict ICMP, RPF
  anti-spoofing, rate-limited logging of dropped packets, block forwarding
  (forward policy drop; off by default so Docker/libvirt/VPNs keep working)
- Validation before apply (`core::validate`): one validator for the rule form,
  the sidebar and the apply / Save to System paths; profiles may contain invalid
  rules, but applying is refused while an applied rule is invalid
- Readable nft errors: when nft rejects a ruleset, each error names the rule
  (user or base rule, by its comment), chain or header that caused it, with the
  offending line and caret; the GUI's "Verification Errors" panel opens the rule
- Root-side revert guard (`core::apply_guard`): one elevation applies the rules
  and starts a detached root watcher that restores the previous table unless
  the user confirms in time, even if DRFW or the session dies
- Rule evaluator (`core::evaluate`): what the generated input chain does with a
  new TCP/UDP connection, and which rule decides; for an unknown source, the
  set of sources that can connect (documented approximations in the module)
- Exposure view (`core::exposure`, GUI "Exposure"): listening sockets read
  unprivileged from `/proc/net`, each evaluated against the editor and the
  applied rules ("reachable from: everyone / sources / nobody / local only");
  process names only for the user's own processes (no root for this)

### Not Implemented (Intentional)
- **Per-rule ICMP type filtering:** 99% of users don't understand 20+ ICMP types; ICMPv6 filtering is dangerous (the global strict ICMP mode allows a fixed set of essential types)
- **Source port matching:** <1% use case
- **TCP flags matching:** Too advanced for target audience
- **MAC filtering:** LAN-only, easily spoofed
- **Time-based rules:** Complex UI, better handled by cron

### Deferred
- **NAT/Port forwarding:** Different scope; would be separate major feature
- **Custom expressions:** Security risk; defeats GUI purpose

---

## 12. Development Workflow

### Toolchain
- **Pinned:** `rust-toolchain.toml` pins the exact Rust release; `rust-version` in `Cargo.toml` matches it (MSRV == pinned toolchain, no separate MSRV job).
- **Bumping:** When a new stable is installed, bump both deliberately in one commit and fix any new clippy lints in that same commit. CI's non-blocking "latest-stable" job gives early warning of upcoming lints.
- **Formatting:** `rustfmt.toml` uses nightly-only options (grouped `std` / external / crate imports, formatted doc examples), so format with the dated nightly: `cargo +nightly-2026-11-14 fmt`. Stable `cargo fmt --check` accepts the result (it only warns about the options it skips), but nightly is authoritative. Bump the date in CLAUDE.md, README and CI together.

### Pre-Commit Checklist
```bash
cargo +nightly-2026-11-14 fmt --check  # nightly rustfmt (rustfmt.toml uses unstable options)
cargo clippy --all-targets -- -D warnings  # pedantic lints configured in Cargo.toml
cargo test
cargo build --release
cargo deny check  # advisories/licenses (config in deny.toml)
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
The library is compiled once and its modules are `pub`, so rustc does not flag
unused `pub` items in them; `#[allow(dead_code)]` is never needed for an item
that only the CLI, the tests or `tools/` use. To find dead library code, make
the `pub mod`s in `lib.rs` `pub(crate)` temporarily and run `cargo build --lib`
(items used by `main.rs`, `tests/` or `tools/` show up too; check them).

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
- `0o600` - User read/write (configs, audit logs, profiles, `drfw.log`)
- `0o700` - User read/write/execute (directories; `ensure_dirs()` also tightens existing ones)

**Required locations:**
- Audit log: `~/.local/state/drfw/audit.log` (0o600)
- App log: `~/.local/state/drfw/drfw.log` (0o600, appended, rotated to `drfw.log.1` past 5 MiB)
- Config: `~/.local/share/drfw/config.json` (0o600)
- Profiles: `~/.local/share/drfw/profiles/*.json` (0o600; directory 0o700)
- Revert guard state: `/run/drfw/` (root-owned 0755 tmpfs dir; `active`, `status-*` 0644)
- Confirm/revert tokens: `$XDG_RUNTIME_DIR` or the state dir, which must be owned by
  the user and 0700 or stricter; tokens 0600
- Last ruleset applied and kept (`core::confirmed`): `~/.local/state/drfw/confirmed-ruleset.json` (0o600)
- Boot config: `drfw::SYSTEM_NFT_PATH` (0644) with `.drfw-bak` and `.drfw-orig`; its
  directory is created 0755 if missing

**Windows:** Document that users should configure ACLs on data directories (`%LOCALAPPDATA%\drfw\drfw\data`).

---

**Last Updated:** 2026-11-20 (kept-ruleset record shared by GUI and CLI, retention
guard, short `StateUnknown` banner with Apply Details. Before: audit fixes: signal-safe guard with the watcher started
before the apply, `StateUnknown`; user rules before ICMP; per-source Accept-only;
split inverted rate+connection limits; `drfw save`; CLI exit codes; elevation context;
no polkit rule. Earlier: chrono → jiff, diagnostics view model, `drfw check`/honest `status`, docs for the revert guard, single generator and Save to System; `distro` compile-time config, boot persistence, enable-at-boot, `print-service-unit`)
**DRFW Version:** 0.9.0
**Iced Version:** 0.14
