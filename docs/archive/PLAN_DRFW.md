# PLAN.md — DRFW (Dumb Rust Firewall)

**Role:** Principal Rust Engineer & Linux Systems Architect (design document)  
**Project:** **DRFW** — *Dumb Rust Firewall* — a tiny, safe, stateful nftables GUI generator for desktop Linux.  
**Philosophy:** extremely conservative defaults, tiny and focused surface area, GUI-first (iced). Present a reliable `inet`-family default firewall and only allow small, well-validated user rules (open TCP/UDP ports, optional interface or source CIDR). Safety-first: always use the JSON API for nftables (libnftables / nft --json fallback), never interpolate shells for privileged calls, always verify before apply, snapshot before change, and auto-revert on timeout.

---

## Contents
1. Goals & high-level scope
2. Phase breakdown (Measure Twice → Implementation)
3. File structure & coding standards
4. Core logic: JSON-first nftables design (exact verification steps)
5. Atomic apply workflow & Dead-Man Switch (detailed)
6. Input validation & sanitization rules
7. Iced GUI — full UI layout & interactions (complete)
8. Persistence, system integration & install considerations
9. Testing strategy (unit / integration / CI)
10. Failure modes, observability & recovery instructions
11. Deliverables & acceptance criteria
12. Appendix: command examples, pseudo-code & hints

---

## 1 — Goals & high-level scope
- Produce a single **GUI-only** Rust app (iced + tokio) that:
  - Uses a JSON-first approach to nftables for generation/verification/apply — prefer libnftables JSON API (via bindings/FFI) or the `nft --json` interface as *fallback*, never freeform text shells.
  - Generates a **simple stateful inet nftables** ruleset (safe default: DROP input/forward, ACCEPT output, allow loopback, allow established/related, allow ICMP).
  - Lets users add/remove simple user rules (TCP/UDP port open, optional source CIDR, optional interface).
  - Applies rules transactionally and safely with automatic revert if the user does not confirm (Dead-Man Switch).
  - Is not a daemon — one-shot apply tool driven from the GUI.
- Target platform: desktop Linux distributions that provide nftables and polkit/pkexec. Primary testing target: Arch Linux desktop but design to work on other systemd/polkit distros where supported.
- Security constraints: JSON-first interaction with nftables to avoid shell parsing; strict sanitization of all user inputs; elevation hygiene (no shell, pass args directly); audit logs and clear recovery instructions.

---

## 2 — Phase breakdown & milestones (GUI-first)

### Phase 1 — Research & PLAN approval (this document)
- Deliver: this PLAN.md (DRFW version)
- Tasks:
  - Confirm JSON API approach & identify binding strategy (libnftables via FFI/bindings crate or a thin local helper that consumes JSON and calls libnftables).
   - Choose iced version and lock minimal dependency list, including: \`nftables = { version = "0.6", features = ["tokio"] }\` to ensure non-blocking operation.
  - Get approval on PLAN before coding.

### Phase 2 — Core logic (JSON model + golden tests)
- Implement `src/core/firewall.rs` with:
  - A Rust model for firewall state (tables/chains/rules) and deterministic JSON serializer matching libnftables expected structure.
  - Generator that emits a JSON representation (not text) of the nftables ruleset for the `inet` family.
  - Unit tests (golden master) asserting JSON output equals known-good canonical JSON structures for typical cases (no rules, one rule, multiple rules).
  - A thin JSON-to-file writer using secure temp files; snapshot/restore functions that save JSON snapshots (not raw `.nft` text).
- Deliver: core library + unit tests pass locally.

### Phase 3 — Integration to libnftables JSON API
- Implement an adapter `src/core/nft_json.rs` that:
  - **Strategy:** Use the `nftables` Rust crate (with the `tokio` feature) as the core adapter. This crate wraps the external `nft` binary and manages all process spawning and I/O safely.
  - **Execution Hygiene:** Ensure all interactions use the crate's non-blocking (asynchronous) APIs to prevent the Iced UI from freezing, adhering to the "fast!" goal.
  - Capture and parse JSON structured errors from the `nftables` crate's output to present clear messages in the GUI.
- Deliver: verified JSON apply/check API that does not rely on shell interpolation.

### Phase 4 — Atomic apply, snapshot & revert (JSON-first)
- Complete end-to-end flow using JSON objects:
  - Snapshot current rules as JSON: `nft --json list ruleset` or libnftables JSON dump.
  - Validate pending JSON rules via the API (transaction or check endpoint) and only apply via JSON call to libnftables.
  - Implement Dead-Man Switch transactional flow (15s countdown) and revert by re-applying JSON snapshot.
- Deliver: verified atomic apply + auto-revert using JSON operations.

### Phase 5 — Iced GUI implementation
- Implement full iced GUI per the UI layout in Section 7.
- Wire GUI to core logic: generating JSON, calling verify/apply adapters, showing diffs (JSON → text diff view), and driving the Dead-Man Switch and notifications.
- Deliver: fully functional GUI application.

### Phase 6 — Tests, CI, packaging & docs
- Integration tests in netns (or sandboxed environment) using JSON API mock/shim for `nft` if needed in CI.
- CI ensures clippy/format/tests/pass and runs golden-master JSON tests.
- Provide AUR/PKGBUILD and/or AppImage/Flatpak packaging guidance and README with recovery instructions.
- Deliver: release artifact + docs + packaging hints.

---

## 3 — File structure & coding standards
```
Cargo.toml
README.md
PLAN.md
ci/                         # CI scripts
src/
  main.rs                   # entry point, logging, window init
  app/
    mod.rs                  # iced State, Message, update()
    view.rs                 # pure view functions (rule_card, header, modals)
    ui_components.rs        # small UI helpers
  core/
    firewall.rs             # model -> canonical JSON generator
    error.rs                # app-wide error types, result aliases, ErrorInfo struct
    nft_json.rs             # libnftables JSON adapter (apply, verify, snapshot)
    verify.rs               # verification helpers & parse JSON errors
    tests.rs                # golden master JSON tests
  config.rs                 # serde models, XDG directories, load/save
  elevation.rs              # safe elevation wrapper (no shell; builds Command args)
  utils.rs                  # helpers (validation, uuid, tmp path)
assets/                      # icons, small images
tests/                       # integration tests using JSON shims / netns
```
Coding standards:
- Idiomatic Rust 2024, clippy clean, documented public APIs.
- `tracing` for structured logs; `eyre` (or `color-eyre`) for human-friendly errors.
- Async via `tokio` where necessary; keep UI message loop responsive using iced's `Command::perform` to wrap async tasks.
- Strict separation: core JSON logic must remain independent from UI code to allow testability and future reuse.

---

## 4 — Core logic: JSON-first nftables design (exact verification steps)

### Why JSON-first
- JSON is structured, machine-parseable, and eliminates many shell-parsing and injection hazards. libnftables exposes JSON APIs for building/applying/checking rules; where direct bindings exist, they are preferred for correctness and structured error reporting.
- Keep textual `.nft` preview for user readability, but **do not** use the textual form for verification/apply — use the JSON representation for machine operations and only render text for preview/diffs.

### Canonical JSON generation (spec)
- The generator emits an object representing the entire ruleset for the `inet` family with tables and chains and rules in a deterministic ordering.
- Invariants:
  - Always include: `flush ruleset` equivalent in JSON (i.e., create JSON representing full state to replace working set atomically).
  - `table` inet `filter` with chains `input`, `forward`, `output` and policies `input: drop`, `forward: drop`, `output: accept`.
  - Base safety rules in `chain input` in exact order: `iif "lo" accept`, `ct state established,related accept`. Explicit **ICMP rules** must follow, allowing PMTUD and basic pinging (as below).
    - IPv4: `icmp type { echo-request, fragmentation-needed }`
    - IPv6: `icmpv6 type { echo-request, nd-neighbor-advert, nd-neighbor-solicit, destination-unreachable, packet-too-big, time-exceeded }`
  - User rules are appended *after* these base rules, deterministic ordering (e.g., sorted by insertion timestamp or UUID).
- Output: canonical serde_json `Value` or strongly-typed structs serialized to JSON.

### Verification & dry-run (exact steps)
1. Generate JSON object `pending_json` from the current in-app model.
2. Write `pending_json` to a secure temp file as JSON (0o600) or stream it to libnftables via stdin.
3. Call libnftables `check`/transaction API with the JSON payload (or run `nft --check --json -f <file>`/`nft --json -f <file>` as fallback). Capture structured output.
4. If API returns errors → parse JSON error, present clear translated message in GUI, abort apply.
5. If API returns only warnings → treat as failures by default (unless the user explicitly toggles an advanced override). Show warnings as errors unless user opts in.

---

## 5 — Atomic apply workflow & Dead-Man Switch (JSON-first)

### Preflight (on app startup)
- Check that libnftables bindings (or fallback `nft`) are present and support JSON operations.
- If libnftables bindings are unavailable at runtime, app shows a clear “fallback mode (nft --json)” banner and requires confirmation before applying.
- Create `XDG_STATE_HOME/drfw/` for snapshots/logs (owner-only perms).

### Snapshot (JSON)
- Snapshot current rules as JSON: prefer `libnftables` JSON dump; fallback to `nft --json list ruleset`.
- Save snapshot: `XDG_STATE_HOME/drfw/snapshot-<uuid>.json` with 0o600 permissions and metadata (timestamp, nft version, sha256).

### Apply (user clicks Apply)
1. Generate `pending_json` and perform local JSON verification via libnftables JSON check API.
   - If verification fails → show parsed JSON error and abort.
2. If verification passes → call the atomic apply via JSON (libnftables transaction API) to load the new ruleset.
3. After apply returns success → enter GUI `PendingConfirmation` state:
   - Start 15-second countdown (configurable) and send desktop notification (notify-rust) with actions (Confirm/Revert).
   - Gray out controls, show big timer, and put a visible “Manual restore” command in the modal.
4. If user confirms within countdown → finalize; optionally prompt to save to `/etc/nftables.conf` via JSON dump + install.
5. If timer elapses → automatically revert by re-applying JSON snapshot via libnftables (or fallback `nft --json -f snapshot.json` invoked safely with Command args).
6. Always capture and store structured apply/verify results in audit log for diagnostics.

### Elevation & execution hygiene (mandatory)
- The app must **never** pass user strings to a shell. All elevation must be done by constructing `Command` with explicit args (e.g., `pkexec` + `nft --json -f /path`) or by calling libnftables FFI directly in-process (preferred).
- Validate `pkexec` presence and show fallback instructions if it is absent.
- Present `stderr` or JSON error bodies verbatim in the diagnostic modal for power users.

---

## 6 — Input validation & sanitization rules
- **Port:** digits only, 1–65535.
- **CIDR:** use a robust parser (e.g., `ipnetwork` or `ipnet` crate) to validate IPv4/IPv6 CIDR canonical forms.
- **Interface:** restrict to `[A-Za-z0-9_.-]{1,15}` or specific kernel acceptance rules; validate existence optionally via `ip link` (read-only check).
- **Labels:** optional, limited length (e.g., 64), strip dangerous characters; store as metadata not used for operations.
- **Rule cardinality:** default cap (e.g., 128 user rules) to prevent extremely large rulesets.
- **Sanitization philosophy:** accept and canonicalize inputs at the model level; errors surfaced to the user. Never embed unsanitized strings into JSON fields that will be interpreted as commands.

---

## 7 — Iced GUI — full UI layout & interactions (complete)

**One-line goal:** minimal, clear, desktop-friendly. Open app → add rules → preview → Apply → Confirm quickly or auto-revert.

### Top-level window layout (single resizable window)

```
+----------------------------------------------------------------------------------+
| DRFW — Dumb Rust Firewall                   [status: OK]  ⚙️  ?  (Last: 2025-12-21) |
+----------------------------------------------------------------------------------+
|  ┌──────────────────────┐   ┌───────────────────────────────────────────────────┐  |
|  | Rules                |   | Preview / Diff (text & JSON)                     |  |
|  | ───────────────────  |   | ──────────────────────────────────────────────── |  |
|  |  [+] Add Rule        |   |  (read-only monospaced nft preview)              |  |
|  |  • ssh (tcp:22)      |   |  (toggle: Show JSON / Show diff) [Export] [Copy]  |  |
|  |  • http (tcp:80)     |   |                                                   |  |
|  |  • custom (udp:53)   |   |                                                   |  |
|  |                      |   |                                                   |  |
|  └──────────────────────┘   └───────────────────────────────────────────────────┘  |
+----------------------------------------------------------------------------------+
| [Apply]  [Export]            Snapshot: snapshot-<uuid>.json    Logs ▾  Help  Quit |
+----------------------------------------------------------------------------------+
```

- Left: scrollable `rule_list` with `rule_card` entries.
- Right: `preview_panel` showing human-readable text plus JSON view toggle.
- Footer: primary `Apply` button, Export, Snapshot indicator, Diagnostics/Logs.

### Components & helpers (view.rs)

- `header()` — app title, status pill, settings & help icons.
- `rule_list()` — Column of `rule_card`s with Add button top; supports drag to reorder (optional).
- `rule_card(rule)` — concise info line: `[Label] protocol port(s) source iface ▸ Edit ▪ Delete`.
- `add_rule_modal()` — form fields with strong inline validation:
  - Protocol: TCP/UDP/ICMP
  - Port: single or range (1–65535)
  - Source: Any or CIDR (parser validation)
  - Interface: optional (validated)
  - Label: optional
  - Buttons: Add (validates), Cancel
- `preview_panel()` — monospaced text area showing pretty-printed `.nft` text + toggle to view generated JSON. Also provides a "Show diff vs snapshot" toggle that shows a simple side-by-side or inline +/- text diff.
- `apply_confirmation_modal()` — two-stage:
  1. Pre-apply confirmation: "Snapshot saved as X. Proceed?" (Proceed / Cancel)
  2. Post-apply countdown: Big timer (15s), Confirm (✔) and Revert Now (⟲). Show a copyable "Manual restore" command for quick recovery.
- `diagnostics_modal()` — last N audit entries, last JSON error blobs, and copyable manual commands for restore. Option to open logs folder.
- `settings_modal()` — advanced only: elevation template (readonly recommended), dead-man timeout, rule cap, treat-warnings-as-error toggle, family selection (inet/ip/ip6) — marked as advanced with warning text.
- `toast()` — ephemeral messages for copy/export success, rule added/removed, etc.

### Interaction details & micro-UX

- **Add Rule flow:** Click + → modal → validate live (port numeric; CIDR canonical) → Add → rule shows in list → preview updates.
- **Edit/Delete:** Edit fills add modal; Delete shows inline “Undo” toast for 5s.
- **Preview:** Live previews on each change. Toggle JSON view to inspect serialized JSON. Show syntax-highlighted text for `.nft` preview for readability.
- **Apply flow:** click Apply → local JSON verification runs (non-blocking async) → if failed, show parsed JSON errors; if passed, pre-apply modal with snapshot notice → Proceed triggers apply via JSON API → on success, show countdown modal and send desktop notification.
- **Notifications:** send `notify-rust` notifications; include action buttons for Confirm/Revert if supported. If notification action triggers, map to `NotificationActionConfirmed` / `NotificationActionReverted` messages in the app.
- **Diff behavior:** Diff is for readability only; actual operations use JSON. Diff is generated by converting JSON -> canonical text and running a text diff algorithm, or by producing a structural JSON diff for advanced view.
- **Accessibility & keyboard:** `Ctrl+N` Add, `Ctrl+Enter` Apply, `Esc` close modal, `Ctrl+S` Export. Autofocus first input in modals. Provide readable labels and non-color cues for status.
- **Failure UX:** If any verification/apply/revert error occurs, present a modal with a plain-language summary and an expandable raw JSON error block along with a copyable manual restore command.

### State machine (summary)
```rust
enum AppState {
    Idle,
    Verifying, // running JSON check
    AwaitingApply, // verified, pre-apply confirmation
    Applying, // running JSON apply (elevated or FFI)
    PendingConfirmation { deadline: Instant, snapshot: SnapshotMeta },
    Confirmed,
    Reverting,
    Error(ErrorInfo),
}
```

### Messages (Message enum) — examples
```
AddRule
EditRule(Uuid)
DeleteRule(Uuid)
RuleFormSubmitted(RuleForm)
ApplyClicked
VerificationCompleted(Result<VerifyResult, VerifyError>)
ProceedToApply
ApplyCompleted(Result<ApplyResult, ApplyError>)
ConfirmClicked
RevertNowClicked
CountdownTick(Duration)
CountdownExpired
NotificationActionConfirmed
NotificationActionReverted
OpenSettings
SettingsSaved(Settings)
OpenDiagnostics
```
Use `iced::Command::perform` or `tokio::spawn_blocking` to run JSON verification/apply tasks asynchronously and send back messages. Ensure UI remains responsive and disable controls appropriately while in non-idle states.

---

## 8 — Persistence, system integration & install considerations
- Do not auto-write to `/etc/nftables.conf` unless user explicitly selects "Save permanently" after confirming apply.
- Save snapshots and audit logs in `XDG_STATE_HOME/drfw/` with strict permissions.
- If user chooses to install permanently, perform the operation using JSON dump and then use elevation to write `/etc/nftables.conf` (install or write with correct perms) via safe `Command` invocation or FFI helper.
- Include packaging hints: PKGBUILD and Flatpak/AppImage packaging recommendations in README — but implementation is GUI-only.

---

## 9 — Testing strategy (JSON-first)

### Unit tests
- Golden JSON tests for generator (exact expected JSON representation stored under `tests/golden/`).
- Validation unit tests (ports, CIDRs, interfaces).

### Integration tests (sandboxed)
- CI should run integration tests in a sandbox (network namespace) or use a mock libnftables JSON shim so CI does not require root or modify host rules.
- Tests must verify snapshot/apply/revert flow in sandboxed environment or using the shim.

### Property tests & fuzzing
- Use `proptest` to fuzz inputs and assert generator always emits syntactically valid JSON and verification rejects invalid inputs.

### CI checklist
- `cargo fmt -- --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- `cargo audit` / `cargo deny` where feasible

---

## 10 — Failure modes, observability & recovery

### Failure modes
- libnftables bindings not available → fallback mode (`nft --json`) with explicit banner and require user confirmation for apply.
- JSON verification returns errors → show parsed error, abort.
- Elevation failure (pkexec absent or errors) → show copyable manual commands and diagnostic logs; attempt no silent retries.
- Revert fails → show raw error, provide manual instructions and present last-known-good snapshot.

### Observability
- Use `tracing` and write structured audit lines to `XDG_STATE_HOME/drfw/audit.log` (JSON-lines: timestamp, action, file, status, error payload).
- Provide diagnostic modal exposing last N audit entries and raw JSON error payloads.
- Log snapshots and apply attempts including versions (nft/libnftables, app version).

### Recovery commands (copyable)
- If using fallback `nft` (only as last resort): `pkexec nft --json -f /path/to/snapshot-<uuid>.json` or `sudo nft -f /path/to/snapshot-<uuid>.nft` (app provides whichever matches saved snapshot format). Prefer JSON route shown to the user.

---

## 11 — Deliverables & acceptance criteria

### Deliverables
- `PLAN.md` (this DRFW version)
- `src/` implementation per file structure emphasizing JSON-first core + iced GUI.
- Golden JSON unit tests and integration sandbox tests.
- CI configuration to run clippy/format/tests/audit.
- README with install & recovery instructions, PKGBUILD / packaging hints.

### Acceptance criteria
- Generator unit tests (golden JSON) produce deterministic canonical JSON matching expected outputs.
- JSON verification (libnftables or `nft --json`) is used and failures surfaced to the user.
- Snapshot & revert flow is exercised in integration tests and works in sandboxed environment.
- Elevation step is done without invoking a shell; tests assert Command arg construction or direct FFI.
- GUI displays apply + 15s countdown and handles confirm/revert paths with notifications.

---

## 12 — Appendix: JSON commands & pseudo-code (hints)

### Fallback via nft `--json`
- Snapshot: `nft --json list ruleset` → save JSON snapshot.
- Verify: `nft --json -c -f /path/to/pending.json` or stream JSON to stdin safely with `Command` and capture structured output.
- Apply: `pkexec nft --json -f /path/to/pending.json` (use `Command::new("pkexec").args([...])`, no shell). Capture exit code & JSON output and parse.
- Revert: `pkexec nft --json -f /path/to/snapshot.json`

### Pseudo-code (verification & apply)
```rust
let pending_json = core::firewall::to_json(&model)?;
let temp = secure_tempfile_in_xdg("drfw-pending-")?;
serde_json::to_writer(&temp, &pending_json)?;

// verify via FFI or fallback:
let verify = nft_json::verify_from_file(temp.path()).await?;
if !verify.success() {
    // parse structured error and show to user
}

// apply via FFI or fallback
let apply = nft_json::apply_from_file(temp.path()).await?;
if !apply.success() {
   // attempt revert or show error
}

// start 15s countdown and send notification
```

---

## Quick checklist (top-level)
- [ ] Preflight checks (libnftables or nft --json) implemented on startup.
- [ ] Generator produces canonical JSON representation.
- [ ] JSON temp-file + JSON verification implemented.
- [ ] Elevation executed without shells; prefer FFI or safe Command args.
- [ ] Snapshot before apply + 15s countdown + notification + automatic revert.
- [ ] Golden JSON unit tests for generator.
- [ ] Integration tests in sandbox or with JSON shim.
- [ ] CI runs clippy/fmt/tests/audit.
- [ ] Recovery instructions available in UI and README.

---
