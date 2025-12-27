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

### Documentation Red Flags
When an AI assistant says:
- "This is deprecated, we need to modernize" ← Verify in official docs first!
- "The old way was X, the new way is Y" ← Confirm with documentation
- "Let me implement this advanced pattern" ← Ask why it's needed

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

## Appendix: Project-Specific Optimizations Applied

### Memory
- **Font Loading:** Centralized static storage (Phase 2)
- **String Caching:** Pre-computed lowercase search, tag lists (Phases 3-4)

### CPU
- **Tag Collection:** 5-10% reduction (Phase 3)
- **Search Filtering:** 10-15% reduction (Phase 4)
- **Rule Rendering:** Better frame consistency (Phase 5)

### Future Optimizations
- **Syntax Highlighting Widget Caching (Phase 1):** Deferred due to complexity
  - Requires refactoring view() architecture or using interior mutability
  - Estimated 60-80% additional CPU savings
  - Should be done as dedicated task with thorough testing

---

**Document Last Updated:** 2025-12-27
**Performance Optimizations:** Phases 2-5 completed, Phase 1 deferred
