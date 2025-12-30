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
- **Test Environment Variables**: Use `unsafe` blocks when setting/removing environment variables in tests (required since Rust 1.82):
  ```rust
  #[test]
  fn test_with_env_var() {
      unsafe {
          std::env::set_var("DRFW_TEST_NO_ELEVATION", "1");
      }
      // ... test code ...
      unsafe {
          std::env::remove_var("DRFW_TEST_NO_ELEVATION");
      }
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

#### Elevation Strategy
DRFW uses different elevation methods with automatic fallback:

1. **Preferred (all modes)**: `run0` when available (systemd v256+, better security, no SUID)
2. **CLI fallback**: `sudo` for standard CLI workflow
3. **GUI fallback**: `pkexec` for graphical authentication

**Benefits of run0:**
- No SUID bit (better security)
- Uses polkit for authentication (like pkexec)
- Automatic adaptation: GUI dialog if polkit agent available, terminal fallback otherwise
- Better process isolation via systemd

**DO NOT:**
- Create custom authentication dialogs (security complexity, maintenance burden)
- Wrap pkexec with stdin piping (not supported, pkexec doesn't accept password on stdin)
- Use sudo with NOPASSWD in sudoers (bypasses authentication entirely)
- Implement PAM directly (synchronous API conflicts with async GUI)

**Invocation:**
```rust
// Prefer run0 everywhere (better security, no SUID)
if binary_exists("run0") {
    Command::new("run0").arg("nft").args(args)
}
// Fall back based on environment
else {
    use std::os::fd::AsFd;
    let is_atty = nix::unistd::isatty(std::io::stdin().as_fd()).unwrap_or(false);

    if is_atty {
        Command::new("sudo").arg("nft").args(args)
    } else {
        Command::new("pkexec").arg("nft").args(args)
    }
}
```

#### Privilege Escalation Patterns
- **Minimize Elevated Code Paths**: Keep privileged operations isolated in dedicated modules (e.g., `elevation.rs`).
- **Binary Availability Checks**: Verify `pkexec` and `nft` are available at startup using `check_elevation_available()`.
- **Timeout Protection**: All elevated operations must have timeout (default: 2 minutes) to prevent indefinite hangs.
- **Validate BEFORE Elevation**: Run `nft --check` (syntax validation) before attempting elevated apply.
- **Error Translation**: Translate pkexec exit codes to user-friendly messages:
  ```rust
  match exit_code {
      Some(126) => ElevationError::AuthenticationCancelled,  // User clicked Cancel
      Some(127) => ElevationError::AuthenticationFailed,      // Wrong password
      Some(1) if stderr.contains("Cannot run program") => ElevationError::NftNotFound,
      _ => /* ... */
  }
  ```
- **Audit All Privileged Operations**: Log all firewall rule applications, system saves, and privilege escalations with timestamps and outcomes.
- **Snapshot Before Modify**: Always capture current state before applying changes for rollback capability.

#### Error Handling for Elevation
Use structured error types with user-facing translations:
```rust
#[derive(Debug, thiserror::Error)]
pub enum ElevationError {
    #[error("pkexec not found - please install PolicyKit")]
    PkexecNotFound,
    #[error("nft binary not found - please install nftables")]
    NftNotFound,
    #[error("Authentication cancelled by user")]
    AuthenticationCancelled,
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Operation timed out after {0:?}")]
    Timeout(Duration),
    // ...
}
```

#### Test Mode
Set `DRFW_TEST_NO_ELEVATION=1` to bypass pkexec/sudo in tests:
```rust
if std::env::var("DRFW_TEST_NO_ELEVATION").is_ok() {
    Command::new("nft").args(args)  // Direct execution for testing
} else {
    // Use sudo or pkexec depending on environment
    create_elevated_nft_command(args)
}
```

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

---

## 9. Iced 0.14 GUI Framework Best Practices

### Correct Styling Pattern (CRITICAL)
**✅ CORRECT: Closure-Based Styling**
```rust
// This is the official Iced 0.14 pattern for custom themes
button("Save")
    .style(|theme: &AppTheme, status| {
        button::Style {
            background: Some(theme.accent.into()),
            text_color: theme.fg_on_accent,
            // ... custom styling
        }
    })

container(content)
    .style(|theme: &AppTheme| {
        container::Style {
            background: Some(theme.bg_surface.into()),
            border: Border { radius: 8.0.into(), ..Default::default() },
            // ... custom styling
        }
    })
```

**❌ WRONG: Implementing Catalog Traits for Application-Level Themes**
```rust
// DO NOT DO THIS unless you're building a widget library or theme system replacement!
impl button::Catalog for AppTheme {
    type Class<'a> = ButtonClass;  // ← Leads to trait ambiguity hell
    fn style(&self, class: &Self::Class<'_>, status: Status) -> Style { ... }
}

impl container::Catalog for AppTheme {
    type Class<'a> = ContainerClass;  // ← Multiple traits with same associated type name
    fn style(&self, class: &Self::Class<'_>) -> Style { ... }
}
// Result: 100+ "ambiguous associated type" compiler errors
```

### When to Use Catalog Traits
The `Catalog` trait is an **advanced feature** for:
- Creating widget libraries that need to work with multiple theme systems
- Replacing `iced::Theme` entirely with a custom theme architecture
- Building reusable component libraries with pluggable styling

**For application development:** Use closure-based styling with your custom theme struct.

### Theme Architecture
```rust
// Good: Simple custom theme struct
pub struct AppTheme {
    pub bg_base: Color,
    pub fg_primary: Color,
    pub accent: Color,
    // ... semantic color fields
}

// Use throughout app with closures
let theme = &self.theme;
button("Click").style(move |_, status| {
    button::Style {
        background: Some(theme.accent.into()),
        // ...
    }
})
```

### Accessing Built-In Themes (Optional)
If you want to support both custom themes AND Iced's built-ins:
```rust
pub enum ThemeChoice {
    Custom(AppTheme),
    IcedBuiltin(iced::Theme),
}

impl ThemeChoice {
    pub fn accent(&self) -> Color {
        match self {
            Self::Custom(t) => t.accent,
            Self::IcedBuiltin(t) => t.palette().primary,
        }
    }
}
```

**Do NOT** implement Catalog traits to achieve this. Use delegation instead.

### UI Styling Reference (MANDATORY)

**CRITICAL:** Before making ANY changes to UI styling, theming, shadows, buttons, modals, or visual design:

1. **Read `STYLE.md` first** - This is the canonical UI style guide for DRFW
2. **Follow established patterns** - Don't invent new styling approaches unless explicitly needed
3. **Update `STYLE.md`** - Document any new styling patterns or decisions you implement
4. **Check the changelog** - Review recent styling changes to understand design evolution

**`STYLE.md` contains:**
- Design philosophy and core principles
- Semantic color system documentation
- Shadow system implementation and usage patterns
- Button styling centralization and categories
- Tab strip design rationale
- Modal window styling standards
- Font picker patterns
- What was rejected and why (critical for avoiding repeated mistakes)
- Performance considerations for UI rendering

**Never:**
- Create inline button styles (use centralized functions from `ui_components.rs`)
- Implement Catalog traits for application-level themes
- Use gradients on interactive elements (breaks shadows in Iced 0.14)
- Modify existing style functions without checking all usage sites
- Add new UI patterns without documenting them in `STYLE.md`

**When uncertain about styling:** Consult `STYLE.md` sections on the specific component type (buttons, modals, tabs, etc.) before proceeding.

---

## 10. GUI Performance Optimization

### Critical Principle: Avoid Regenerating Widgets Every Frame
Iced calls `view()` at 30-60 FPS. Creating thousands of widgets per frame destroys performance.

### Anti-Pattern: Heavy Computation in view()
```rust
// ❌ BAD: Syntax highlighting runs every frame (30-60 times per second!)
pub fn view(&self) -> Element<'_, Message> {
    let highlighted = syntax_highlight(&self.cached_text, theme); // Regenerates 100+ widgets
    container(highlighted).into()
}
```

### Optimization Pattern: Cache in State, Invalidate on Change
```rust
// ✅ GOOD: Pre-compute in update(), reference in view()
pub struct State {
    cached_text: String,
    cached_tags: Vec<String>,          // Phase 3: Computed once per ruleset change
    search_lowercase: String,           // Phase 4: Computed once per keystroke
}

fn update(&mut self, message: Message) {
    match message {
        Message::RuleChanged => {
            self.cached_text = self.compute_text();
            self.cached_tags = self.compute_tags();  // Only when data changes!
        }
        Message::SearchChanged(s) => {
            self.search_lowercase = s.to_lowercase();  // Cache lowercase once
            self.search = s;
        }
    }
}

pub fn view(&self) -> Element<'_, Message> {
    // Just reference cached data, no recomputation
    for tag in &self.cached_tags { ... }
    if label.contains(&self.search_lowercase) { ... }
}
```

### Performance Optimizations Implemented in DRFW

#### Phase 2: Font Memory Leak Fix
**Issue:** `Box::leak()` for every font family (100+ individual leaks)
**Fix:** Single controlled leak of `Vec<String>` storage
```rust
static FONT_NAMES_STORAGE: OnceLock<&'static [String]> = OnceLock::new();
let font_names: &'static [String] = FONT_NAMES_STORAGE
    .get_or_init(|| Box::leak(families.into_boxed_slice()));
// One leak instead of 100+
```
**Impact:** 10-100MB memory savings

#### Phase 3: Cache Tag Collection
**Issue:** Allocating `BTreeSet` and iterating all rules every frame
**Fix:** Pre-compute in `update_cached_text()`
```rust
pub struct State {
    cached_all_tags: Vec<String>,  // Pre-sorted, pre-deduplicated
}

fn update_cached_text(&mut self) {
    let all_tags: BTreeSet<String> = self.ruleset.rules.iter()
        .flat_map(|r| r.tags.iter().cloned())
        .collect();
    self.cached_all_tags = all_tags.into_iter().collect();
}
```
**Impact:** 5-10% CPU reduction

#### Phase 4: Cache Lowercase Search Term
**Issue:** Calling `.to_lowercase()` on every rule, every frame
**Fix:** Cache on input change
```rust
Message::RuleSearchChanged(s) => {
    self.search_lowercase = s.to_lowercase();  // Once per keystroke
    self.search = s;
}
```
**Impact:** 10-15% CPU reduction

#### Phase 5: Pre-Allocate Collections
**Issue:** `.fold(column![].spacing(8), ...)` reallocates repeatedly
**Fix:** Pre-allocate Vec
```rust
let mut rule_cards = Vec::with_capacity(filtered_rules.len());
for rule in filtered_rules {
    rule_cards.push(build_card(rule));
}
column(rule_cards).spacing(8)
```
**Impact:** Better frame consistency, reduced allocations

#### Phase 6: Dynamic Horizontal Scrolling Width
**Issue:** Horizontal scrollbar always visible even when content is narrow, or zebra stripes extend unnecessarily far when switching views.

**Challenge:** Iced's `scrollable` with `Direction::Both` requires explicit content width. There's no automatic content measurement like `Length::Shrink` for wrapped layouts.

**Solution:** Calculate width dynamically based on current view content:
```rust
// State stores separate width for each view
pub struct State {
    cached_nft_width_px: f32,    // NFT view (active rules only)
    cached_json_width_px: f32,   // JSON view (fixed structure)
    cached_diff_width_px: f32,   // Diff view (includes disabled rules)
}

// Calculate in update_cached_text() when content changes
fn calculate_max_content_width(tokens: &[HighlightedLine]) -> f32 {
    const CHAR_WIDTH_PX: f32 = 8.4; // Monospace char at 14pt
    const LINE_NUMBER_WIDTH_PX: f32 = 50.0;
    const TRAILING_PADDING_PX: f32 = 60.0; // Breathing room (~7 chars)
    const MIN_WIDTH_PX: f32 = 800.0; // Minimum for aesthetics
    const MAX_WIDTH_PX: f32 = 3000.0; // Safety cap

    let max_char_count = tokens.iter()
        .map(|line| line.indent + line.tokens.iter().map(|t| t.text.len()).sum())
        .max()
        .unwrap_or(0);

    let content_width = LINE_NUMBER_WIDTH_PX
        + (max_char_count as f32 * CHAR_WIDTH_PX)
        + TRAILING_PADDING_PX;
    content_width.clamp(MIN_WIDTH_PX, MAX_WIDTH_PX)
}

// Select width in view() based on current tab and diff state
let content_width = match (state.active_tab, state.show_diff) {
    (WorkspaceTab::Nftables, true) => state.cached_diff_width_px,
    (WorkspaceTab::Nftables, false) => state.cached_nft_width_px,
    (WorkspaceTab::Json, _) => state.cached_json_width_px,
    _ => state.cached_nft_width_px,
};
```

**Why This Works:**
1. **Not a workaround** - This is the correct solution for Iced's architecture. Explicit dimensions are required for bidirectional scrolling.
2. **Character-based calculation** - Standard text rendering approach (char count × monospace width).
3. **Follows existing patterns** - Uses "cache in update(), reference in view()" pattern from Phase 3-4.
4. **Minimal cost** - One iteration per content change (not per frame), negligible performance impact.

**Edge Cases Handled:**
- ✅ Diff view showing disabled long rules (uses `cached_diff_width_px`)
- ✅ Tab switching NFT ↔ JSON (no jarring scrollbar jumps)
- ✅ Toggling diff on/off (smooth layout shift on explicit user action)
- ✅ Empty rulesets (`.unwrap_or(0)` fallback)
- ✅ JSON view consistently narrow (<800px, uses minimum for aesthetics)

**Trailing Padding (60px):**
- Prevents zebra stripes from feeling cramped at line endings
- Gives visual breathing room (~7 characters worth)
- Prevents scrollbar for "barely too long" lines
- Improves overall aesthetics

**Layout Shift Behavior:**
- Width adjusts when user explicitly changes views (tab switch, diff toggle)
- This is **intentional and acceptable** - user action triggers expected layout change
- More precise than fixed "max of all views" approach
- Prevents unnecessarily wide zebra stripes when longest line isn't in current view

**Impact:** Scrollbar appears only when current view genuinely needs it, zebra stripes match actual content width, comfortable visual spacing

### String Allocation Minimization
```rust
// ❌ BAD: Allocates String every frame
let port_text = format!("{}-{}", p.start, p.end);

// ✅ GOOD: Stack-allocated buffer for integers
use std::fmt::Write;
let mut buf = String::with_capacity(12);
write!(&mut buf, "{}-{}", p.start, p.end).ok();
```

### Pre-Allocation Best Practices
```rust
// Always reserve capacity when you know the size
let mut nft_rules = Vec::with_capacity(estimated_capacity);
let mut out = String::with_capacity(300 + (self.rules.len() * 50));
```

---

## 11. Common Pitfalls & Lessons Learned

### The Catalog Trait Trap (2025-12-27 Incident)
**What Happened:** An LLM assistant saw the `Catalog` trait example in Iced documentation and assumed it was required for custom themes. It implemented 10 different Catalog traits on `AppTheme`, causing:
- 168 compiler errors from trait ambiguity
- Type inference failures throughout view layer
- 5 hours of wasted development time
- Broken working code

**Root Cause:** Misunderstanding of Iced's architecture. The `Catalog` example in docs is for **library authors**, not **application developers**.

**Correct Understanding:**
- Iced's built-in `Theme` implements `Catalog` with `Box<dyn Fn(...)>` as the Class type
- This allows closures to be used directly as styles
- Application developers should use closures, not implement Catalog

**Red Flags to Watch For:**
- Any suggestion to "implement Catalog traits for your custom theme"
- Creating semantic style enums like `Container::Card`, `Button::Primary` for application code
- "Type-locked helper" patterns to work around inference issues
- Compiler errors about "ambiguous associated type `Class`"

**If You See These:** Stop immediately. The approach is wrong. Use closure-based styling instead.

### Widget Caching Challenges
**Issue:** Iced's `view()` takes `&self`, so you can't mutate caches during rendering.

**Attempted Solutions:**
1. ❌ Interior mutability (`RefCell`) - Runtime overhead, not idiomatic
2. ❌ Lazy generation in view() - Can't mutate with &self
3. ✅ Pre-generate in `update()` when data changes - Correct approach

**Best Practice:** Compute expensive view state in `update()`, store in State, reference in `view()`.

### Modal Width Calculations & Wrapped Layouts (2025-12-28 Theme Picker)

**What Happened:** During theme picker implementation, we spent significant time trying to achieve pixel-perfect padding symmetry between cards and scrollbar through exact width calculations.

**Initial Approach (Wrong):**
```rust
// Calculating exact modal width from card requirements
const MODAL_WIDTH: f32 = (CARD_WIDTH * 3.0) + (CARD_SPACING * 2.0) + (GRID_PADDING * 2.0) + 50.0;
```
- Brittle: Breaks with any layout change
- Fragile: Requires recalculation when adding features
- False precision: Iced's wrapped rows don't work this way

**Correct Approach:**
```rust
// Choose comfortable width, fine-tune by ±10px for visual balance
const CARD_WIDTH: f32 = 150.0;
const CARD_SPACING: f32 = 16.0;
const GRID_PADDING: f32 = 8.0;
const MODAL_WIDTH: f32 = 556.0; // Fine-tuned for visual balance
```

**Key Insights:**
1. **Wrapped rows only expand to content width**, not container width - extra space appears on right
2. **This is normal Iced behavior** - don't fight it with complex calculations
3. **Use symmetric padding everywhere** - asymmetric padding to "fix" scrollbar gaps is a code smell
4. **Choose comfortable width with slack** (~20-30px extra) for scrollbar overlay
5. **Fine-tune by ±10px if needed** - minor visual adjustments are acceptable
6. **Won't break with font size changes** - fixed card widths are resilient

**The Scrollbar Saga:**
We went through multiple iterations trying to achieve perfect padding:
- Adding extra right padding → huge left gap appeared
- Reducing modal width → cards clipped by scrollbar
- Asymmetric padding calculations → confusing and fragile
- **Solution:** Increased modal width to 556px with symmetric 8px padding

**Lesson:** When layout feels "hacky" or requires advanced math, step back. Choose simple constants, add some slack, and fine-tune visually. Don't pursue pixel perfection at the cost of maintainability.

**Reference:** See `STYLE.md` "Theme Picker Patterns" section for detailed implementation.

### Performance Profiling Guidelines
**Before Optimizing:**
1. Profile with real workloads (100+ rules, not 5)
2. Use `cargo build --release` for realistic measurements
3. Identify actual bottlenecks with `cargo flamegraph`

**Common False Optimizations:**
- Micro-optimizing cold paths (initialization code)
- Premature abstraction (creating helpers before measuring impact)
- Over-engineering (RefCell when simple caching works)

**Real Wins:**
- Caching computed state in update()
- Pre-allocating collections with known sizes
- Avoiding allocations in hot loops (view())

### Privilege Escalation: The Custom Auth Dialog Trap (2025-12-29)

**What Happened:** During privilege escalation improvements, we researched alternatives to pkexec including custom authentication dialogs using PAM, building a custom polkit authentication agent, and polkit policy files for better UX.

**Why We Didn't Pursue Custom Auth:**
1. **Security complexity**: Custom auth dialogs require SETUID binaries or capabilities, creating massive attack surface
2. **PAM synchronous API**: Conflicts with async Iced GUI (blocks event loop)
3. **Maintenance burden**: Must handle edge cases like multiple polkit agents, session types, display servers
4. **1-2 weeks minimum**: Basic version needs 1-2 weeks, hardened version 3-4 weeks
5. **pkexec already works**: It's the Linux desktop standard used by GNOME, KDE tools

**Why We Didn't Use Polkit Policy Files:**
1. **Complexity vs. benefit**: 40+ lines of fallback logic for a slightly prettier auth dialog
2. **Low adoption**: Most users (<20%) would have the policy installed
3. **Minimal UX difference**: Generic pkexec dialog is clear enough
4. **Works everywhere**: Plain pkexec requires no installation/configuration

**Attempted Solutions:**
1. ❌ Custom PAM dialog with Iced - Synchronous API blocks GUI
2. ❌ Wrap pkexec with stdin - pkexec doesn't accept password on stdin (security design)
3. ❌ Custom polkit authentication agent - Complex, security-critical, high maintenance
4. ❌ Polkit policy with fallback logic - Too complex for minimal UX gain
5. ✅ run0 (preferred) + pkexec (GUI) + sudo (CLI) - Simple, works everywhere, better security

**The Research:**
- Examined 7+ approaches (PAM, polkit, D-Bus daemon, capabilities)
- Analyzed real-world examples (GUFW, firewalld, Soteria authentication agent)
- Researched available Rust crates (pam-client, zbus_polkit, runas, sudo-rs)
- **Final conclusion**: Keep it simple - plain pkexec/sudo is sufficient

**Lesson:** Don't reinvent authentication systems. Use the platform-provided mechanism (pkexec for GUI, sudo for CLI) without unnecessary complexity.

**Reference:** See Section 5 "Privilege Escalation Safety" for implementation details.

### Documentation Red Flags
When an AI assistant says:
- "This is deprecated, we need to modernize" ← Verify in official docs first!
- "The old way was X, the new way is Y" ← Confirm with documentation
- "Let me implement this advanced pattern" ← Ask why it's needed
- "We should build a custom authentication dialog" ← See privilege escalation trap above

**Golden Rule:** If code works and follows official examples, it's probably correct. Don't fix what isn't broken.

---

## 12. Development Workflow Checklist

### Before Making Architectural Changes
- [ ] Read official documentation for the specific version
- [ ] Verify current code is actually wrong (not just "different")
- [ ] Check if "improvement" solves a real problem or creates new ones
- [ ] Test that current code compiles and runs correctly

### Performance Optimization Workflow
- [ ] Profile to identify actual bottlenecks (use `cargo flamegraph`)
- [ ] Implement fix for highest-impact issue first
- [ ] Test that optimization doesn't break functionality
- [ ] Measure improvement (before/after CPU usage, frame times)
- [ ] Document optimization in code comments

### Code Review Self-Check
- [ ] Does this change make code simpler or more complex?
- [ ] Am I adding abstractions that are actually needed?
- [ ] Have I tested the change with realistic data (100+ items)?
- [ ] Will this be maintainable by someone unfamiliar with the codebase?

---

## 13. nftables Features: Implementation Decisions

This section documents nftables capabilities that DRFW intentionally does NOT implement, either permanently or deferred until a user-friendly solution exists.

### Features NOT Implemented (Intentional)

#### ICMP Type Filtering
**Decision:** Not implementing per-rule ICMP type filtering.

**Reasoning:**
- Baseline firewall already handles common cases (strict mode blocks redirects)
- Established/related connection tracking allows ICMP replies automatically
- 99% of custom ICMP rules just need "allow from this IP" (all types)
- ICMPv6 type filtering is dangerous (blocking wrong types breaks IPv6 entirely - NDP, PMTU, router discovery)
- Users don't understand the difference between 20+ ICMP types
- 1% who need granular control can manually edit nftables config

**Alternative Provided:**
- Global "Strict ICMP filtering" in Advanced Security Settings
- Protocol option: "ICMP (Both)" for dual-stack simplicity

#### Per-Rule Logging
**Decision:** Not implementing per-rule logging in rule creation UI.

**Reasoning:**
- Logs go to kernel ring buffer (`dmesg`/`journalctl`), not DRFW-specific logs
- Requires terminal/sudo access to view (breaks GUI-first experience)
- Output format is cryptic kernel log format mixed with other system logs
- High-traffic rules generate massive log spam (1000 req/sec = 1000 log entries/sec)
- Easy to accidentally DoS the system logs without realizing it
- Not user-friendly for DRFW's target audience (desktop users)

**Alternative Provided:**
- Global "Log dropped packets" with rate limiting in Advanced Security Settings
- Future: Could add Diagnostics tab viewer for kernel firewall logs

#### Source Port Filtering
**Decision:** Not implementing source port (sport) matching.

**Reasoning:**
- Extremely niche use case (<1% of users)
- Only useful for specific scenarios (e.g., DNS responses from port 53)
- Destination port filtering covers 99% of needs
- Adds complexity to UI for minimal benefit

#### TCP Flags Matching
**Decision:** Not implementing TCP flag filtering (SYN, ACK, RST, etc.).

**Reasoning:**
- Too advanced for target audience (requires TCP protocol knowledge)
- Baseline firewall handles connection state tracking (established/related)
- Potential for users to break legitimate traffic by misunderstanding flags
- Power users can manually edit nftables for advanced stateful filtering

#### Packet Length / Size Matching
**Decision:** Not implementing packet size filtering.

**Reasoning:**
- Very niche use case (fragmentation attacks, covert channels)
- Not useful for typical desktop/server firewall needs
- Adds complexity without clear user benefit

#### MAC Address Filtering
**Decision:** Not implementing MAC address filtering.

**Reasoning:**
- Only works on LAN (doesn't cross routers)
- Easily spoofed (not a security mechanism)
- Fragile (MAC changes when NIC is replaced)
- Better handled at switch/AP level with 802.1X

#### Time-Based Rules
**Decision:** Not implementing time/schedule-based rules.

**Reasoning:**
- Complex UI (time pickers, timezone handling, recurring schedules)
- Better handled by external tools (cron + nftables reload)
- State management complexity (what happens when rule becomes inactive mid-connection?)
- Very niche use case

### Features Deferred (May Add Later)

#### NAT / Port Forwarding
**Status:** Deferred for future major feature addition.

**Reasoning:**
- Different feature scope entirely (not just filtering)
- Requires understanding of masquerading, DNAT, SNAT
- Complex UI (internal/external IP, port mapping)
- Needs separate nftables table/chains
- Would be a major feature release, not incremental addition

**When to Add:**
- When DRFW expands scope to include router/gateway functionality
- When user demand is significant (currently 0 requests)
- As a separate "Port Forwarding" tab, not in rule creation

#### Custom nftables Expressions
**Status:** Deferred indefinitely.

**Reasoning:**
- Would allow advanced users to inject arbitrary nftables syntax
- Security risk (command injection, breaking firewall)
- Defeats purpose of GUI (just edit nftables directly at that point)
- Validation complexity

**Alternative:**
- Users needing custom expressions should edit `/etc/nftables.conf` directly
- DRFW manages its own table (`drfw`) at priority -10, doesn't interfere

### Features Implemented (For Reference)

✅ **Protocol filtering:** TCP, UDP, TCP+UDP, ICMP (Both), ICMP (v4), ICMPv6, Any
✅ **Destination port filtering:** Single port or range
✅ **Source IP filtering:** Single IP or CIDR network
✅ **Interface filtering:** Match specific network interface
✅ **Chain selection:** Input/Output (Server Mode only)
✅ **Enable/Disable rules:** Without deleting them
✅ **Rule ordering:** Drag-and-drop priority
✅ **Tags:** Organize and filter rules

**Advanced Options (Implemented 2025-12-29):**
✅ **Destination IP filtering:** For outbound traffic control in Server Mode
✅ **Action selection:** Accept/Drop/Reject
✅ **Per-rule rate limiting:** Prevent brute force attacks
✅ **Connection limiting:** Max simultaneous connections per source

---

## Appendix: Project-Specific Optimizations Applied

### Memory
- **Font Loading:** Centralized static storage (Phase 2)
- **String Caching:** Pre-computed lowercase search, tag lists (Phases 3-4)

### CPU
- **Tag Collection:** 5-10% reduction (Phase 3)
- **Search Filtering:** 10-15% reduction (Phase 4)
- **Rule Rendering:** Better frame consistency (Phase 5)

### UX / Layout
- **Dynamic Horizontal Scrolling:** Intelligent width calculation per view (Phase 6)
  - Scrollbar only appears when current view genuinely needs it
  - Zebra stripes match actual content width (no unnecessary extension)
  - 60px trailing padding for comfortable visual spacing
  - Layout shifts on explicit user actions (tab switch, diff toggle)

### Future Optimizations
- **Syntax Highlighting Widget Caching (Phase 1):** Deferred due to complexity
  - Requires refactoring view() architecture or using interior mutability
  - Estimated 60-80% additional CPU savings
  - Should be done as dedicated task with thorough testing

---

**Document Last Updated:** 2025-12-30
**Performance Optimizations:** Phases 2-6 completed, Phase 1 deferred
**Advanced Rule Options:** Implemented destination IP, action, rate limiting, connection limiting
**Privilege Escalation:** Simplified to plain pkexec (GUI) + sudo (CLI), removed polkit policy complexity
**Horizontal Scrolling:** Dynamic width calculation with view-specific sizing (Phase 6)
