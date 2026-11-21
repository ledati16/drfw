# DRFW Development Standards

**Purpose:** Development guidelines for agents and contributors working on DRFW, a safe,
transparent nftables firewall for Linux, with a GUI and CLI. This file states the rules
and the design the code relies on; history belongs in git and `CHANGELOG.md`.

**Principles:** Security-first, performance-conscious, test-driven, maintainable code.

---

## 1. Code Quality

### Linting & Static Analysis
- **Strict compliance:** Clippy pedantic lints enabled in `Cargo.toml`; CI runs clippy with
  `-D warnings` (see §12 for the exact commands)
- **Centralized config:** Crate-wide allows live in `[lints.clippy]` in `Cargo.toml`, each
  with a one-line rationale; no crate-level `#![allow(...)]` in `lib.rs`, `main.rs` or
  `tests/*.rs`
- **Local allows:** A per-item `#[allow(...)]`/`#[expect(...)]` only when the reason is
  specific to that item, with a one-line comment giving it (`#[expect]` also flags it once
  it is no longer needed). Never repeat a lint the central config already allows
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
- **CI checks the docs:** `cargo doc` runs with `RUSTDOCFLAGS="-D warnings"`, so broken
  intra-doc links fail the build

### Naming in User-Facing Text
Docs, GUI text, CLI help and code comments use the same words:
- **"Block forwarded traffic"** for the setting (not "block forwarding" or "forward
  blocking")
- **"Forwarded rules"** / **"Forwarded (routed through)"** for the forward chain in user
  terms; `Chain::Forward` only when talking about code
- **"Kept"** for the record concept: a ruleset is "applied and kept" (a confirmed guard or
  `--no-confirm`); the file is still `confirmed-ruleset.json`
- **"Server Mode"** (capital M, everywhere); the other egress mode is "Desktop mode"

### Modern Rust Patterns
- **Safety first:** No `unwrap()` in production paths; use `?` or `expect()` with context
- **Early returns:** Use `let-else` and guard clauses to minimize indentation
- **Visibility:** Default to private; widen only when architecturally required
- **Efficiency:** Prefer in-place operations (`clone_from`) over reallocations

### DRY Principle
- **Extract** a pattern used 3+ times, a complex one (5+ lines), or one that would cause
  bugs if its copies drifted apart (e.g. `utils::block_on_async`, `ButtonStyleConfig` in
  `ui_components.rs`, `audit::log_event_internal`)
- **Don't extract** trivial (1-2 line) patterns, or where extraction would obscure intent
- **Verify before extracting:** code that looks alike may differ (append vs truncate, sync
  vs async); merge only paths that are really identical
- **Wait for 3+ identical uses** before creating a helper; inline code beats a poor
  abstraction

### File Size and Splitting
- **Soft limit:** consider a split past ~3000 lines with clear logical sections; logical
  cohesion beats line counts
- **Group by domain:** `app/view/` (one file per panel/dialog), `app/handlers/` (rules,
  apply, profiles, settings, ui_state, export, exposure), pure helpers in `app/helpers/`
- **Handler modules:** module docs state the domain; related handlers together; tests at
  the bottom of the same file

**Splitting checklist:**
1. Read the whole file first; count functions before and after
2. Diff every multi-statement inline handler line by line against the original
   (counting functions does not verify logic)
3. Check internal calls you might now duplicate (e.g. `mark_profile_dirty()` already
   calls `update_cached_text()`)
4. Run the §12 commands after each phase, then test the affected GUI features by hand
5. Add unit tests for extracted handlers

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
Chosen by the pure `select_elevation()` (inputs gathered by `current_elevation()`,
table-tested), from the `ElevationContext` the front end sets once at startup
(`elevation::set_context`: `Gui` in `run_gui()`, `Cli` in `main()`):

1. **Already root:** run directly (no prompt)
2. **`DRFW_ELEVATION_METHOD`** (`sudo`/`run0`/`pkexec`): forced method (which tool
   asks; there is no password-less mode)
3. **GUI:** always `pkexec`, even when started from a terminal (`run0`/`sudo` would
   prompt invisibly in that terminal); no `pkexec` → `PkexecNotFound`
4. **CLI (or no context set):** stdin is a TTY → `run0` (systemd v256+, no SUID) if
   installed, else `sudo`; no TTY → `pkexec`

Every elevated child uses `kill_on_drop(true)`. DRFW ships **no polkit rule**: every
elevated operation asks once. Caching `/bin/sh` would allow arbitrary root commands;
caching `nft` makes root `nft` (a file-read primitive: `nft -c -f <file>` echoes lines
in errors) available to anything that can drive the DRFW process, only to save a
prompt in the rare elevated-check fallback. Never suggest sudoers `NOPASSWD` for
unattended applies: the elevated program is `/bin/sh`, so that is full root. Automation
that already runs as root runs `drfw` as root (nothing is elevated then).

**Rejected approaches:** custom auth dialogs (security complexity, maintenance burden),
PAM directly (synchronous API conflicts with the async GUI), piping passwords to stdin
(`pkexec` doesn't support it by design).

### Root-Side Revert Guard (dead-man switch)
`core/apply_guard.rs` + `APPLY_SCRIPT`/`WATCHER_SCRIPT`. As root, in one elevation:

0. `trap '' HUP INT QUIT TERM PIPE` (an SSH drop or Ctrl-C after the password must not
   stop the script halfway), then print `drfw-apply-started` (DRFW now knows the
   script runs as root: a later timeout or signal means "state unknown", not
   "nothing changed"). Take the `flock` on `/run/drfw/lock`.
1. Save the current `inet drfw` table (stdout of `nft list table` only) or the fact
   that there is none as an atomic revert batch in root-owned `/run/drfw`
   (`GUARD_STATE_DIR`). If an earlier guard is still pending, inherit its revert file:
   a timeout returns to the last *kept* state.
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
A watcher stopped by `TERM`/`HUP`/`INT` (`systemctl stop`, `kill`, shutdown) without a
status file reverts at once (`on_signal`); only `SIGKILL` ends it without a revert, and
`drfw status` then reports "LOST since …" (`WatcherState::Gone`) instead of PENDING.

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
**and** at least 40 % of its enabled rules removed or changed (matched by id; disabled =
removed; a kept rule edited to act differently, `same_effect` false, = changed: Accept→Drop,
narrowed sources, moved chain, …; the line then reads "Removes or changes N of the M …"),
Desktop→Server, or "Block forwarded traffic" turned on. GUI: computed in `update()`
(`ApplySession::retention`, `SaveToSystemDialog::retention`); only the "Apply anyway"
button (`Message::ProceedToApplyAnyway`) proceeds, Enter (`ProceedToApply`) is refused,
and `SaveToSystemDialog::primary_source()` never picks the editor's rules then. CLI
(`confirmation_guard` in `main.rs`, which also runs the SSH lockout check, §11): prints
the same `lines`, asks y/N once on a terminal, otherwise needs `--yes` (exit code 9,
nothing changed). Lockout notes (access only limited) are printed without a question.

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
profile whose JSON is not the kept-ruleset record (see above) prints a loud "not the
one last applied and kept; no dead-man switch at boot" warning and needs `--yes` (no
TTY) or a y/N answer (exit 7 otherwise); `confirmation_guard` follows (exit 9). With
`--enable-at-boot` a failed enable exits 8; without it a disabled boot service is warned
about. Tests set `DRFW_TEST_SYSTEM_NFT_PATH` (honoured only together with
`DRFW_NFT_COMMAND`).

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
scripts' `safe_path`, and stricter: no empty or `.` components) and
`is_valid_service_name`, so a bad value fails the build. `is_script_path` is exactly the
scripts' `safe_path` (absolute, allowlist, no `..` component; a differential proptest
keeps the shell function and it in step). `unprivileged_nft()` is the `nft` DRFW runs
itself (the namespace check); the real-nft tests probe and use the same one.
`build.rs` has `rerun-if-env-changed` for all three. `contrib/drfw.service.in` is the
unit template; `drfw print-service-unit` (hidden) fills it with these values, and the
PKGBUILD installs that output. Never hard-code `/etc/nftables.conf` or `nft` paths
elsewhere; tests must compare against the constants (packagers build with overrides).

### Security Requirements
- **Validate, then verify, then apply:** `validate_for_apply()` → `nft --check` → apply
- **Timeout protection:** 2-minute maximum for anything that can show an auth dialog
- **Error translation:** Map exit codes to user actions (126=cancelled, 127=auth failed)
- **Audit logging:** Log all privileged operations with timestamps
- **Test bypass:** `DRFW_NFT_COMMAND` (set by the tests themselves, §6) runs that nft or
  `tests/mock_nft.sh` directly, without elevation

### Subprocess Timeouts
Every subprocess call has a timeout: async children via
`tokio::time::timeout(.., child.wait_with_output())` with `kill_on_drop(true)` (see
`APPLY_TIMEOUT`, `SAVE_TIMEOUT`, `ELEVATED_CHECK_TIMEOUT`). `std::process::Command` has
none; use it only for calls that cannot hang, or run it under a timeout (`tokio::process`
or a thread), or document the possible hang in the function docs.

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
`list`/`apply`/`status`/`save`/`check`/`export`/`exposure` commands and the hidden
`print-service-unit`, the countdown) and uses the
library through its public API (`drfw::…`). Never re-declare library modules
with `mod` in `main.rs`: that compiles them twice, as two incompatible copies,
and runs their unit tests twice. Inside the library, always write `crate::…`;
`drfw::…` belongs in `main.rs`, `tests/`, `tools/` and doctests.

CLI facts the docs promise (keep them true): `--confirm` outside 5–120 is a clap usage
error (exit 2), and the GUI clamps a hand-edited `auto_revert_timeout_secs` into the
same range; keys typed before the countdown starts (e.g. during the password prompt)
are discarded; output into a closed pipe (`drfw … | head`) ends quietly instead of
panicking (exit 101 before); without git metadata the version is plain "0.9.0" and
`--version` reports commit and branch "unknown" (`build_info`).

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
| `src/distro.rs` | Compile-time validators, service unit template | `is_valid_absolute_path()`, `is_script_path()`, `is_valid_service_name()`, `service_unit()` |
| `src/elevation.rs` | Unit + property tests for elevation, without touching the environment | Method selection table (`select_elevation`: root, `DRFW_ELEVATION_METHOD`, context, TTY, installed tools), command shapes per tool, `DRFW_NFT_COMMAND` precedence, the shell `safe_path` vs `distro::is_script_path` (differential proptest, three locales) |
| `src/core/boot.rs` | `systemctl` output mapping | `enablement_from_output()`, `BootStatus` summaries and checkbox rules |
| `tests/integration_tests.rs` | End-to-end tests with mock nft, CLI binary, profiles | Mock verification **plumbing** (one pass, one refusal) and the mock's own input checks, guarded-apply plumbing (incl. a killed apply script → `StateUnknown`, guard still reverts; which applies write the kept-ruleset record), CLI `status` (incl. the SSH line)/`check`/`save`/`exposure` (table and `--json` shape on a `/proc` fixture)/`print-service-unit`, the retention guard and the SSH lockout check of `apply`/`save` (exit 9, `--yes`; a rate-limited SSH rule is a note without exit 9; interface-bound SSH against a `drfw-test-addresses` fixture; `SSH_CONNECTION` on the child only) and the `--help` exit codes (runs the real binary, in a hermetic environment), argument validation of both root scripts (every argument, unsafe state dirs; exit 1 and nothing created), save script incl. enable-at-boot (fake `systemctl`), `drfw export` output, audit log writes, profile load rebuilds caches |
| `tests/real_nft.rs` | Real `nft` in `unshare -rn` (own binary) | Text output loads, JSON and text give identical kernel rulesets (proptest), idempotent reload, no widening, per-source sets (replaced on apply, clients kept apart), Server Mode loopback, a user Drop rule blocks ping (two netns), interface length limit vs nft, Save to System script, revert guard end to end (incl. SIGHUP/INT/TERM/KILL right after the rules went live, tokens of other uids ignored) |
| `src/core/evaluate.rs` | Unit tests for the rule evaluator | Chain model (order, family copies, skipped rules), limits/conditions as `Limited`, reachability sets (subtracted drops, `AllExcept`, conditional access, caveats), **the modelled chain has the generator's base rules (by their real comments) in the generator's order** for every setting that changes it, ICMP section after the user rules |
| `src/core/addr_set.rs` | Unit tests for the address-set arithmetic | Union/intersection/difference/complement, CIDR decomposition |
| `src/core/exposure.rs` | Unit tests for socket discovery | `/proc/net` parsing (IPv4, IPv6, v4-mapped, UDP, established connections), inode → process mapping and `scan_host_in` on a fixture tree, dual-stack heuristic, exposure rows |
| `src/core/lockout.rs` | Unit tests for the SSH lockout check | `SSH_CONNECTION` parsing (IPv4, IPv6, zones, mapped, malformed), which `/proc` connections count as SSH, merging, blocked / may-be-blocked / limited (note) / accepted and the cause split, address → interface (ambiguous, loopback, aliases, fixture file), Server Mode output order (established accepted before user rules) |
| `src/app/exposure.rs` | Unit tests for the Exposure panel model | Row order and badges, editor vs applied answers, scan errors, "SSH:" lines |
| `tests/evaluate.rs` | Evaluator property tests; kernel agreement in two `unshare -rn` namespaces over veth (own binary re-executed as server/client helpers) | Per-source verdicts agree with the reachability sets (proptest); **the evaluator agrees with real nft** on random rulesets and probes (proptest) and directed cases |
| `tests/verify_errors.rs` | Error attribution against real `nft` in `unshare -rn`, and `drfw check` output (own binary) | A rejected ruleset names the rule that caused each error (also with per-source sets), CLI prints mapped errors without color codes |
| `tests/profile_storage.rs` | Profile/config files on disk (own binary; tests serialized because they set `DRFW_TEST_DATA_DIR`) | Corrupt/newer/oversized profiles, duplicate ids, no-replace create/rename, file modes, config recovery |
| `tests/baseline.rs` | The base rules in the kernel: namespace labs over veth (`unshare -rn`, own binary as UDP helper; skips without `ip`, `nsenter`, `ping`, `timeout`, … unless `DRFW_REQUIRE_REAL_NFT=1`) | ICMP redirects of a live flow dropped (PMTU discovery still works), IGMP in and (Server Mode) out, DHCP client replies (also broadcast), local network discovery, RPF (spoofed sources dropped, full-tunnel VPN underlay kept), ICMP rate limit vs a ping flood, loopback destinations from the network dropped, Forwarded rules with "Block forwarded traffic" |
| `src/core/validate.rs` | Unit + property tests for the validator | Every rule/ruleset issue type, valid rules always validate |
| `src/core/rule_constraints.rs` | Field-combination helpers shared by the form and `stress_gen` | Which protocols take ports, ICMP family vs IP version, TCP reset only for pure TCP, reject types per protocol, chain → interface kind |
| `src/validators.rs` | Unit + property tests for input validators | Ports, interfaces (length incl. `*`, wildcard position, Unicode/zero-width/RTL rejected), label sanitizing (length, idempotence, control chars, emoji, homoglyphs), log prefix, rate/connection/log-rate limits |
| `src/core/confirmed.rs` | The kept-ruleset record | Round trip (bytes, ruleset, kind, boot id), record from an earlier boot, legacy bare-JSON record, missing/garbage/newer records ignored, unreadable ruleset keeps the JSON |
| `src/core/retention.rs` | The retention guard | Thresholds (3 and 40 %), matching by id, disabled = removed, capped rule names, mode changes |
| `src/core/templates.rs` | Rule templates | Server Mode essentials, VM guest/Tailscale/"Trust <interface>" rules, `available_templates()` by interface name |
| `src/app/templates.rs` | The "Add from template" menu model | Only templates for present interfaces, fresh rules on every use, VM template notes and duplicates |
| `src/core/host_facts.rs` | Host facts on a `/proc` fixture | Forwarding flags, forwarding notice only when not blocked, `docker-proxy` command lines, published-port matching, container bridges |
| `src/core/system_config.rs` | Save to System output mapping | Backup path and `enable=` outcome read from the script's stdout |
| `src/core/profiles.rs` | Profile parsing and storage | No `version` = 1, newer version refused (even when unparseable), corrupt profile, round trip writes `version`, no-replace rename, the unreadable-profile message |
| `src/config.rs` | Config loading | Old configs keep auto-revert off and get no notice, active-profile salvage |
| `src/command.rs` | Undo/redo commands | Apply/undo of each command (incl. adding several rules, enabling Server Mode with its rules), history size cap, a new command clears redo |
| `src/main.rs` | CLI unit tests (bin test target) | Countdown key classification and rounding, CLI usage examples parse, exit codes distinct and documented, `drfw exposure` table and JSON |
| `tests/root_e2e.rs` | `#[ignore]`d helpers for the disposable root e2e kit (`tools/e2e/run.sh`); no-ops without `DRFW_E2E_DISPOSABLE=1` | Save to System through the real elevation tool and the real `nft -c` |
| `tests/common/mod.rs` | Helpers shared by the integration crates (`mod common;`): real-nft probe and `nft`/`unshare` with the library's `nft`, root-script path check, rule builders on `Rule::with_caches`, `write_profile`, `EnvVarGuard` | - |
| `src/core/test_helpers.rs` | Shared lib test utilities (Rule/Ruleset creation, mock setup, `CHRONO_TIMESTAMPS`) | - |
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
```

**Lib tests never change the process environment** except `setup_mock_nft()` (sets
`DRFW_NFT_COMMAND` once, never removes it): a test that unset it would let another
test run the real `nft` and the elevated fallback. Test environment-dependent logic
through pure functions with the inputs passed in (`elevation::select_elevation`,
`nft_command`, `save_config_command`). Safety net: in lib tests (`cfg(test)`) elevating
and using the real data/state directories panic (`utils::deny_in_lib_tests`). Compute
such paths inside the async task, not when scheduling it.

**Note:** Integration tests in `tests/` (like `src/main.rs` and `tools/stress_gen.rs`) are separate crates that link the library and see only its `pub` API; they **cannot access `#[cfg(test)]` modules** from the library. Helpers shared by several integration crates live in `tests/common/mod.rs` (each crate declares `mod common;`); prefer the public `Rule::with_caches` constructor there over struct literals, so a new `Rule` field does not have to be added to every test file. Keep the library's `test_helpers` and `tests/common` in step when Rule fields change.

### Environment Variables

| Variable | Purpose | When to Use |
|----------|---------|-------------|
| `DRFW_NFT_COMMAND` | Path to nft binary or mock script (skips elevation) | Set by the mock-based tests themselves (`setup_mock_nft()`, or on the child `Command`). Do **not** export it for `cargo test`: the real-nft tests need the real `nft` and skip (or fail under `DRFW_REQUIRE_REAL_NFT=1`) when it is set |
| `DRFW_TEST_DATA_DIR` | Overrides data directory (`~/.local/share/drfw/`) | Tests that access profiles |
| `DRFW_TEST_STATE_DIR` | Overrides state directory (`~/.local/state/drfw/`) | Tests that access the audit log |
| `DRFW_TEST_PROC_DIR` | Read instead of `/proc` by the socket and SSH session scan and the host facts (`core::exposure::proc_root`); its `drfw-test-addresses` file (`name address` lines) replaces the interface addresses of the lockout check (`core::lockout::local_addresses`; none when missing, the real interfaces are never read) | CLI tests of `exposure`/`status`/`apply`/`save`: a fixture tree, or a missing dir for "no sessions" (the CLI test helpers always set one) |
| `SSH_CONNECTION` | The session the SSH lockout check protects (not a DRFW variable) | Set on the **child** only; the CLI test helpers remove it so the runner's own SSH session never leaks in. GUI handler tests never read it (`State::new_for_testing` has no session; set `state.ssh_sessions`) |
| `DRFW_REQUIRE_REAL_NFT` | `1` makes the real-nft tests (`tests/real_nft.rs`, `tests/evaluate.rs`, `tests/verify_errors.rs`, `tests/baseline.rs`) fail instead of skipping when `unshare -rn nft` (or a tool the lab needs) is unavailable | CI (set); never in packaging `check()` |
| `DRFW_GUARD_STATE_DIR` | Guard state dir of the apply script in test mode (only read when `DRFW_NFT_COMMAND` is set; default `<state dir>/guard`, instead of root's `/run/drfw`). `tests/mock_nft.sh` also looks there for `mock-kill-apply` (kill the script mid-apply) | Guarded-apply tests in `tests/integration_tests.rs` |
| `DRFW_TEST_SYSTEM_NFT_PATH` | Target file of `drfw save` instead of `drfw::SYSTEM_NFT_PATH`; honoured only together with `DRFW_NFT_COMMAND` (nothing elevated) | CLI `save` tests |
| `DRFW_E2E_DISPOSABLE` | `1` lets `tools/e2e/run.sh` and the `#[ignore]`d `tests/root_e2e.rs` helpers write as root (also needs a VM/container, or `DRFW_E2E_ALLOW_BARE_METAL=1`); without it they refuse or are no-ops | Only on a disposable VM/container |
| `DRFW_ELEVATION_METHOD` | Not a test variable: forces the elevation tool (`sudo`, `run0`, `pkexec`; case-insensitive, empty = unset, anything else is an error), e.g. `sudo` over SSH where `run0` is installed but unusable | Users. Tests never export it; `select_elevation` is table-tested with the value passed in, and `tools/e2e/run.sh` unsets it |

For tests that run the `drfw` binary (`env!("CARGO_BIN_EXE_drfw")`), set these on the
child `Command`, not with `std::env::set_var`: per-child env cannot race other tests.

`systemctl` has no override variable on purpose (an env var that picks the program
root runs would be one more thing to audit). Tests put a fake `systemctl` first on the
**child's** `PATH` instead: `tests/integration_tests.rs` (`FAKE_SYSTEMCTL`) does this
for the save script (`create_elevated_save_config_command(..).env("PATH", ..)`) and
for every `drfw` child: `drfw_command()` starts from an empty environment (only
`TMPDIR` is kept), so the runner's SSH session, `DRFW_*` variables and systemd never
leak in. Paths handed to the root scripts must pass their `safe_path`; tests that need
that skip with a notice (`common::script_paths_usable()`) when the checkout or
`TMPDIR` has e.g. a space.

### Test Style
- `#[tokio::test]` only when the test awaits something (verify, apply, profile I/O);
  `#[test]` for pure transformation, validation and cache rebuilding
- Mock-based lib tests call `setup_mock_nft()` first (safe before any `.await`)
- Validators get example tests plus `proptest` properties (length caps, idempotence,
  no control/Unicode characters)

### CI/CD Compatibility
- No test needs privileges. Tests use the mock nft, or the real `nft` inside a private
  user + network namespace (`unshare -rn`), never the host's ruleset
- The real-nft tests skip themselves without `nft`/user namespaces; CI installs nftables
  (and `jq` for the mock), allows user namespaces and sets `DRFW_REQUIRE_REAL_NFT=1` so a
  skip is a failure. CI runs the suite twice: with the default compile-time paths and
  with a packager's (`DRFW_SYSTEM_NFT_PATH`, `DRFW_SYSTEM_NFT_SERVICE`, `DRFW_NFT_PATH`);
  tests must use `drfw::SYSTEM_NFT_SERVICE` etc., never the default literals
- The non-blocking latest-stable CI job installs no nftables: its real-nft tests skip
- Document any special requirements in module-level docs

How to run the suite: the command list in §12. Mock-based tests set `DRFW_NFT_COMMAND`
themselves (`setup_mock_nft()`; the mock needs `jq`). Do not run
`DRFW_NFT_COMMAND=tests/mock_nft.sh cargo test`: the real-nft tests need the real `nft`.
Tests never require root and never touch the host's nftables, but the real-nft tests do
run the real `nft` (and the kernel's nftables) inside a private namespace.

### Stress Test Generator
`tools/stress_gen.rs` (feature `stress_gen`) writes profiles that cover every protocol,
action, chain, reject type and rate-limit unit:
```bash
cargo run --bin stress_gen --features stress_gen -- --count 500 --edge-cases -o profiles/edge-cases.json
cargo run --bin stress_gen --features stress_gen -- --scenario chaos --seed 12345 --verify --report -o profiles/chaos.json
```
`--scenario`: minimal (10), typical (50), enterprise (200), chaos (1000) rules; `--seed`
makes a run reproducible, `--verify` runs `nft --check` on the result, `--report` prints
the distribution.

### TODO Comments
Give a TODO an owner or issue reference; update or remove it when the plan changes or
the work is done (no stale "Phase N" notes).

### Handler Test Coverage
GUI handlers (`src/app/handlers/*.rs`) are mostly orchestration (update state, spawn a
`Task` that elevates, opens a file dialog or runs `nft`) and are not unit tested by
design. Test their pure helpers (`truncate_error_message`,
`interpret_elevated_command_output`) and simple state changes; the external paths are
covered by `tests/`. Add targeted tests where bugs appear.

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

### Rules
- **Cache in state, once per change:** lowercase search strings (once per keystroke),
  filtered/sorted collections (once per data change; e.g. the diagnostics event log
  formats rows once per load and the visible indices once per filter/search change),
  syntax-highlighting tokens (once per text change), display strings of rules
  (`Rule::rebuild_caches()`). `view()` only references them.
- **Pre-allocate** (`Vec::with_capacity`, `String::with_capacity`) when the size is known;
  use `&'static str` / `.into()` instead of `to_string()` for constant text.
- **UI examples:** `STYLE.md` §9 (cached display strings, allocations in `view()`, picker
  filtering).
- **Debounce disk writes:** a setting change marks state dirty (`mark_config_dirty()`,
  `mark_profile_dirty()`), never saves directly. One-shot, generation-tagged timers
  (`src/app/debounce.rs`, armed by `State::arm_debounce_timers` at the end of every
  `update()`) do the save: no polling subscription, so an idle app does not rebuild its
  view. A timer that fires after newer edits carries a stale generation and is ignored
  (or re-armed for the rest).

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

Validated with 700 varied rules (smooth scrolling, instant search, apply and Save to
System fine): `cached_nft_tokens` and `keyed_column` reconciliation cope, so virtual
scrolling is not needed (it would make variable-height cards jump).

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
Apply always uses `nft --json -f -`; the text form DRFW generates is only ever written to
files and checked with `nft -c` before use. Never parse `nft list` text output for data
(the apply script only checks `nft list tables` for the exact line `table inet drfw`).
Replaying it is fine: the revert batch is the saved `nft list table inet drfw` text,
loaded unchanged with `nft -f`.

### Apply Workflow
1. **Validate:** `validate_for_apply()` (refuses invalid applied rules)
2. **Verify:** `verify_ruleset()`: unprivileged namespace check, elevated `nft --check`
   only if that does not pass. `drfw check` uses `verify_ruleset_unprivileged()` (never
   prompts)
3. **Apply + guard:** `apply_guarded()` (one elevation; see §4)
4. **Confirm or revert:** token file; the root-side watcher reports the outcome

### Rule Ordering
Input chain, in `build_commands()` (the doc comment of `to_nftables_json()` is the
reference; `core::evaluate` models the same order and a test compares them):
1. Loopback accept, `ct state invalid` drop
2. ICMP/ICMPv6 redirect drops: **before** established/related, because a redirect
   quoting one of our connections is `related` (it would be accepted otherwise)
3. With an ICMP rate limit: `icmp(v6) type echo-request limit rate over N/second drop`,
   also before established/related (every echo request of a running ping is
   `established`; a limit after it would only limit new pings)
4. Established/related accept (bulk traffic)
5. Checks of new packets only: drops of 127.0.0.0/8 source/destination from non-`lo`
   (matters with `route_localnet=1`), optional RPF `fib saddr . mark . iif oif missing
   drop`. After established/related so conntrack-vouched replies pass (a full-tunnel
   VPN's underlay, de-NATed container replies to 127.0.0.1); the mark honours fwmark
   policy routing
6. DHCP (`udp sport 67 udp dport 68`) and `DHCPv6` client replies (untracked: the
   request went to broadcast/multicast)
7. User-defined Input rules, in profile order
8. Local network: `ip protocol igmp accept` (always), then with Local network
   discovery (Desktop only) mDNS/SSDP/WS-Discovery multicast accepts by destination
   group and the `@discovery_reply` accepts (unicast from 10/8, 172.16/12, 192.168/16,
   169.254/16, fe80::/10, fc00::/7 to a port that sent a genuine discovery query in the
   last 10 s; the set is filled by the output chain's 7 per-protocol rules)
9. ICMP allow rules (all types, or the strict set; no limit, so neighbor discovery,
   router advertisements and MLD are never rate limited)
10. Optional drop logging (`pkttype host` only), rate-limited reject of unicast
    (comment "rate-limited reject"), counter ("final counter"), then the default policy

User rules come **before** the local network and ICMP allows so a user Drop/Reject rule
("drop everything from X") also stops them. Established/related traffic is accepted
before any user rule: standard stateful behaviour, a Drop rule stops new connections
only (and not ICMP errors related to existing ones). Keep this in README ("Default
Protection").

Output chain: Server Mode adds loopback, invalid drop, established, ND/MLD (incl.
`mld-listener-done`), IGMP and DHCP/DHCPv6 client requests, then Output user rules;
Desktop has no rules except, with local discovery, the 7 discovery query recorders. Forward chain (Forwarded
rules, `Chain::Forward`): with "Block forwarded traffic", invalid drop, established,
then the Forwarded rules (`iifname` and `oifname`); without it nothing (policy accept),
and Forwarded rules are not generated.
`Rule::takes_effect()` says whether a rule is generated (validation and the GUI use it).

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

All logging functions are one-line delegations to `log_event_internal()` (enable check,
`AuditLog` creation, warning on failure).

---

## 11. Firewall Features

### Implemented
- Protocol filtering (TCP, UDP, TCP+UDP, ICMP, ICMPv6, ICMP (both), Any)
- Port filtering: a list of single ports and ranges
- Source filtering: a list of IP addresses/CIDRs (likewise destinations)
- Interface matching (input/output; both on Forwarded rules)
- Enable/disable without deletion
- Rule ordering (drag-and-drop)
- Per-rule logging (with configurable prefix)
- Advanced: action (accept/drop/reject), rate limiting, connection limiting
- Per-source limits: a rate or connection limit can apply per source address
  (IPv6 per /64) through named dynamic sets instead of being shared by all sources.
  **Accept rules only** (`validate.rs`, `PER_SOURCE_ACCEPT_ONLY`; the form hides the
  checkboxes otherwise): a set holds `PER_SOURCE_SET_SIZE` (65535) sources, and once
  it is full new sources are not tracked. For Accept that fails closed (new clients
  fall through to the policy, so a flood from more distinct, e.g. spoofed, addresses
  locks new clients out until it stops); for Drop/Reject it would fail open
- Advanced security: Server Mode (output policy drop), strict ICMP, ICMP rate limit
  (echo requests over N/s dropped), RPF anti-spoofing (strict, new packets only, with
  the mark), rate-limited logging of dropped unicast packets, "Block forwarded traffic"
  (forward policy drop; off by default so Docker/libvirt/VPNs keep working) with
  Forwarded rules (`Chain::Forward`, input and output interface)
- Local network discovery (`local_discovery`, Desktop only, absent = off): mDNS
  (224.0.0.251 / ff02::fb, 5353), SSDP/WS-Discovery (239.255.255.250 / ff02::c /
  ff05::c, 1900/3702) multicast in, and replies to the host's own discovery queries via
  the `discovery_reply` dynamic set (keyed by port only, deliberately). Only genuine
  queries fill it: SSDP/WS-Discovery to those groups on 1900/3702, mDNS to
  224.0.0.251 / ff02::fb on 5353, LLMNR to 224.0.0.252 / ff02::1:3 on 5355, NetBIOS
  name queries broadcast to 137; other broadcast/multicast never opens the sender's
  port. Replies only from 10/8, 172.16/12, 192.168/16, 169.254/16, fe80::/10, fc00::/7.
  No LLMNR multicast listener (poisoning-prone); LLMNR/NetBIOS answers to our queries
  work via the set. NetBIOS datagram (138) is not supported. Exposure: UDP sockets on
  1900/3702/5353/5355/137 read `LOCAL_DISCOVERY` ("local network (discovery)") or
  `LOCAL_DISCOVERY_REPLIES` ("local network, for 10 s after it sends a discovery query")
  when only the replies reach them; other ports are not shown as reachable
- Always-on base rules: IGMP accept (and Server Mode IGMP out), DHCP and DHCPv6 client
  replies, redirect drops before established/related
- Rule templates (`core::templates`): Server Mode essentials (DNS, DoT, NTP,
  HTTP/HTTPS, ping as Output rules), libvirt guest DHCP/DNS on `virbr*`, Tailscale
  direct connections (UDP 41641) and "Trust <interface>"; ordinary rules, nothing
  hidden. `available_templates()` picks them by interface name
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
  process names only for the user's own processes (no root for this); also the
  SSH line per session (below). `drfw exposure [profile] [--json]` prints the same
- SSH lockout check (`core::lockout`): before Apply / Save to System, sessions from
  `SSH_CONNECTION` and `/proc/net/tcp*` (sshd-owned or to an sshd port) are
  evaluated as new connections, on the interface that owns the session's server
  address (`network-interface`; unknown when none, several or `lo` have it; the
  outcome names the assumed interface when it decided). Blocked or "blocked in
  some cases" (an open condition: unknown interface, ...) needs "Apply anyway" /
  "Save anyway" (GUI, the retention guard's pattern) or `--yes` (CLI, exit 9).
  Accepted only up to a rate/connection limit (`Access::Limited`) is a note (info
  block, CLI "Note:"), never a confirmation. The client is assumed to pass RPF.
  Also a line in `drfw status` and the Exposure panel
- Host facts (`core::host_facts`, unprivileged `/proc` reads): notices when the kernel
  forwards while "Block forwarded traffic" is off, and for Docker-published ports and
  container bridges (traffic DRFW's input rules never see); nothing changes the rules.
  A `docker-proxy` counts only when it runs as root (real and effective uid 0) and the
  socket is root's. With "Block forwarded traffic" on, published ports read
  `DOCKER_PUBLISHED_FORWARD_FILTERED` and the note `CONTAINER_NETWORKS_NOTE_FORWARD_FILTERED`
  (`ContainerFacts::note_for`); the core sets `SocketExposure::docker_forward_filtered`
  itself (`evaluate_socket`, `mark_published_by_docker`), the GUI never does. The GUI
  shows these core constants (capitalized), never its own copies

### Not Implemented (Intentional)
- **Per-rule ICMP type filtering:** 99% of users don't understand 20+ ICMP types; ICMPv6 filtering is dangerous (the global strict ICMP mode allows a fixed set of essential types)
- **Source port matching:** <1% use case
- **TCP flags matching:** Too advanced for target audience
- **MAC filtering:** LAN-only, easily spoofed
- **Time-based rules:** Complex UI, better handled by cron

### Rejected Baseline Choices
- **Base rules for specific services** (Tailscale 41641, `tailscale0`, `virbr0`,
  `docker0`): offered as templates instead, visible and removable
- **Loose RPF:** never drops on a host with a default route; strict + mark instead
- **Forward drop by default:** Docker/libvirt accepts in their own tables cannot
  override a drop in ours (final); "Block forwarded traffic" stays opt-in
- **Stealth drop instead of the rate-limited reject:** the reject is unicast-only and
  capped at 5/s total, so it cannot be used for reflection, and clients fail fast

### Deferred
- **NAT/Port forwarding:** Different scope; would be separate major feature
- **Custom expressions:** Security risk; defeats GUI purpose

---

## 12. Development Workflow

### Toolchain
- **Pinned:** `rust-toolchain.toml` pins the exact Rust release; `rust-version` in
  `Cargo.toml` matches it (MSRV == pinned toolchain, no separate MSRV job).
- **Bumping:** bump both deliberately in one commit and fix any new clippy lints in that
  same commit. CI's non-blocking "latest-stable" job gives early warning of new lints.
- **Formatting uses the pinned nightly:** `rustfmt.toml` uses nightly-only options
  (grouped `std` / external / crate imports, formatted doc examples), so format with
  `cargo +nightly-2026-11-14 fmt`. Stable `cargo fmt --check` accepts the result (it only
  warns about the options it skips), but nightly is authoritative. Bump the date in
  CLAUDE.md, README and CI together.

### Pre-Commit Checklist
One list: the checks `.github/workflows/ci.yml` runs, plus the release build. Run all of
them before a commit:
```bash
cargo +nightly-2026-11-14 fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --locked --features stress_gen -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo test --locked                      # DRFW_REQUIRE_REAL_NFT=1 to fail instead of skip when nft is missing
cargo build --release --locked
```
CI sets `DRFW_REQUIRE_REAL_NFT=1`, runs the tests a second time with a packager's
compile-time paths (§6), and runs `cargo deny check` (`deny.toml`; run it locally when
dependencies change).

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

### Rules of Thumb
- **Named constants, no magic numbers** (`SHADOW_LIGHT_ALPHA`, not a bare `0.35`)
- **Flatten conditionals:** past ~3 levels of nesting, extract a named function (e.g. one
  `validate_*` per field) or use `let-else`/guard clauses
- **No `unwrap()` in message handlers:** state can change between a check and its use;
  take the value with `let Some(x) = self.field.take() else { tracing::error!(..);
  return Task::none(); };` and degrade gracefully instead of panicking
- **`unwrap()` is acceptable** in tests, right after a check in the same scope that makes
  failure impossible, and in static initialization where failure is unrecoverable

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
- Revert guard state: `/run/drfw/` (root-owned 0755 tmpfs dir; `active`, `status-*` 0644;
  revert file, watcher script and `lock` 0600)
- Confirm/revert tokens: `$XDG_RUNTIME_DIR` or the state dir, which must be owned by
  the user and 0700 or stricter; tokens 0600
- Last ruleset applied and kept (`core::confirmed`): `~/.local/state/drfw/confirmed-ruleset.json` (0o600)
- Boot config: `drfw::SYSTEM_NFT_PATH` (0644) with `.drfw-bak` and `.drfw-orig`; its
  directory is created 0755 if missing
