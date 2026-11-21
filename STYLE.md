# DRFW UI Style Guide

**Purpose:** Visual consistency standards for DRFW's Iced GUI.

**Principles:** Clarity over decoration, theme-aware, subtle depth, performance-first.

---

## 1. Semantic Color System

**Location:** `src/theme/mod.rs`

### Color Hierarchy
```rust
pub struct AppTheme {
    // Progressive background depth
    bg_base: Color,      // Deepest layer (app background)
    bg_sidebar: Color,   // Sidebar
    bg_surface: Color,   // Cards, containers
    bg_elevated: Color,  // Inputs, buttons
    bg_hover: Color,     // Hover states
    bg_active: Color,    // Selected states

    // Text
    fg_primary: Color,   // Main text
    fg_secondary: Color, // Secondary text
    fg_muted: Color,     // Disabled/placeholder
    fg_on_accent: Color, // Text on colored backgrounds

    // Semantic
    accent: Color, success: Color, warning: Color, danger: Color, info: Color,

    // Borders
    border: Color, border_strong: Color, divider: Color,

    // Syntax (for code preview)
    syntax_keyword: Color, syntax_type: Color, syntax_string: Color,
    syntax_number: Color, syntax_comment: Color, syntax_operator: Color,

    // Shadows
    shadow_color: Color,  // Auto-calculated based on theme luminance

    // Zebra striping
    zebra_stripe: Color,  // Pre-calculated subtle background
}
```

### Usage Rules
- **Never hardcode colors:** Use semantic names, not RGB values
- **Theme-aware calculations:** Check `theme.is_light()` when deriving colors
- **Progressive depth:** Backgrounds get lighter/darker as they elevate

---

## 2. Shadow System

**Location:** `src/theme/mod.rs` (`AppTheme::from_hex`, `SHADOW_LIGHT_ALPHA`, `SHADOW_DARK_ALPHA`)

### Shadow Values
```rust
// Light themes: crisp and visible
shadow_color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),

// Dark themes: visible against dark backgrounds
shadow_color: Color::from_rgba(0.0, 0.0, 0.0, 0.6),
```

Shadow color is auto-calculated in `AppTheme::from_hex()` based on background luminance.

### Elevation Patterns
**Buttons:**
- Rest: `offset: (0.0, 2.0), blur: 4.0`
- Hover: `offset: (0.0, 3.0), blur: 6.0`
- Pressed: `offset: (0.0, 1.0), blur: 2.0`

**Modals/Tooltips:**
- Standard: `offset: (0.0, 2.0), blur: 3.0`

### Critical Constraint
**Gradients break shadows in Iced 0.14.** Interactive elements must choose one:
- Use gradients → no shadow
- Use shadows → solid backgrounds only

This is why tabs use solid backgrounds instead of gradients.

---

## 3. Centralized UI Styles

**Location:** `src/app/ui_components.rs`

### Button Style Functions
```rust
primary_button(theme, status)       // Main actions (Apply, Save)
secondary_button(theme, status)     // Supporting actions (Cancel, Export)
danger_button(theme, status)        // Destructive actions (Delete, Rollback)
card_button(theme, status)          // Large clickable cards (export options)
active_tab_button(theme, status)    // Selected tabs
inactive_tab_button(theme, status)  // Unselected tabs
dirty_button(theme, status)         // Unsaved changes indicator
```

### Container Style Functions
```rust
card_container(theme)               // Standard cards with shadow
active_card_container(theme)        // Selected cards with accent border
popup_container(theme)              // Tooltips, floating menus
inset_container(theme)              // Recessed areas (tag clouds, lists)
inset_container_bordered(theme)     // Recessed areas with visible border
section_header_container(theme)     // Subtle label backgrounds
modal_backdrop(theme)               // Semi-transparent overlay
attention_card_container(theme)     // Card with 2px danger border (open to everyone)
warning_attention_card_container(theme) // Same in warning (open on some interfaces)
info_notice_container(theme)        // Same in info (one-time workspace notices, Exposure notes)
danger_badge_container(theme)       // Solid pill badge, danger ("OPEN TO EVERYONE")
warning_badge_container(theme)      // Solid pill badge, warning ("OPEN ON wg0")
```
Badges always carry text: the color only repeats what the words say.
Exposure rows and notes use the core's wording, never a GUI copy: "local network
(discovery)" / "local network, for 10 s after it sends a discovery query"
(`core::exposure::LOCAL_DISCOVERY`, `LOCAL_DISCOVERY_REPLIES`) are shown as restricted
(no badge, no highlight). A Docker-published port always gets the warning "PUBLISHED BY
DOCKER" badge, with the text `host_facts::DOCKER_PUBLISHED` (warning color, amber card)
or, with "Block forwarded traffic" on, `DOCKER_PUBLISHED_FORWARD_FILTERED` (primary text
color, no card highlight), capitalized ("Published by Docker: decided by your Forwarded
rules (blocked unless one allows it)"). The container note is
`ContainerFacts::note_for()`.
One-time notices above the preview (auto-revert off, local network
discovery off) go through `workspace::one_time_notice`: an "INFO" label, the
sentence, a primary and a secondary answer; either answer hides it for good
(a config flag).

### Implementation Notes
**Buttons:** All button functions use a unified `ButtonStyleConfig` system internally to avoid code duplication. Each button type is defined as a const configuration with specific colors, shadows, and interaction states. **Do not create new button functions**—modify existing configurations or add new const configs to the system.

**Containers:** Use centralized container functions instead of inline styling. `inset_container()` handles theme-aware background calculations (hybrid darkening/brightening) automatically.

### Standard Padding/Sizing
```rust
// Primary action buttons
.padding([10, 24]).size(14)  // Apply, Save

// Secondary/utility buttons
.padding([10, 20]).size(14)  // Cancel, Close, Export

// Tab navigation
.padding([8, 16]).size(13)   // Ruleset, Settings (`workspace::view_tab_button`)

// Filter tags
.padding([4, 8]).size(10)    // Sidebar tag filters

// Small inline buttons
.padding(6).size(14)         // × delete, No/Yes confirmations
```

### Usage Rules
- **Never create inline styles:** Use centralized functions
- **card_button vs secondary_button:** Use `card_button` only for large card-like elements (export options, font cards); use `secondary_button` for standard Cancel/Close buttons
- **Consistent padding:** All buttons in same category must use identical padding

---

## 4. Section Headers

**Location:** `src/app/ui_components.rs:section_header_container()`

### Pattern
```rust
container(text("FILTERS").size(9).font(mono).color(fg_muted))
    .padding([2, 6])  // Small labels: [2, 6]; Larger: [4, 8]
    .style(|_| section_header_container(theme))
```

### Implementation
- **5% opacity** of `fg_primary` color
- **4px border radius**
- **Minimal padding:** [2, 6] for size 9-11, [4, 8] for size 12+

### Where to Use
✅ Sidebar labels, modal titles, form section headers, field labels, footer metadata
❌ Large page titles, dynamic content, body text, action buttons

**Rule:** Only wrap static labels, not dynamic values (e.g., "PREVIEW:" yes, "PREVIEW: Ayu Dark" no).

---

## 5. Font Usage

**Location:** Font values stored in `State` struct, accessed via `state.font_regular` / `state.font_mono`

### Font Types

**Regular Font (`font_regular`)** - User's chosen UI font for readable content:
- Button labels and UI controls
- Form field labels and descriptions
- User input text (search boxes, text inputs for labels/descriptions)
- Modal body text and explanations
- Help text and error messages
- Profile names and user-created tags
- Dropdowns showing user-created content

**Monospace Font (`font_mono`)** - User's chosen monospace font for technical/structural elements:
- Section headers (PROFILE, FILTERS, RULES, etc.)
- Status badges (Unsaved Changes*, Saved)
- Numeric counters (5/10 rules shown)
- Code/configuration previews (the nftables ruleset and its diff)
- Technical identifiers (port numbers, IP addresses, interface names like @eth0)
- Protocol badges (TCP, UDP, ICMP)
- Line numbers in code views

### Accessing Fonts

**Pattern 1: Functions with `state: &State` parameter**
```rust
fn view_sidebar(state: &State) -> Element<'_, Message> {
    text("PROFILE").font(state.font_mono)      // Section header
    text_input("Search...", &state.rule_search).font(state.font_regular)  // User input
}
```

**Pattern 2: Functions with font parameters**
```rust
fn view_rule_form(
    form: &RuleForm,
    theme: &AppTheme,
    regular_font: iced::Font,
    mono_font: iced::Font,
) -> Element<Message> {
    text("DESCRIPTION").font(regular_font)     // Label
    text_input("80", &form.port_start).font(mono_font)  // Port number
}
```

### Widget Font Methods

**All text widgets support `.font()`:**
```rust
text("Label").font(font)
text_input("placeholder", &value).font(font)
button(text("Save").font(font))
checkbox(enabled).label("Enable").font(font)
pick_list(items, selected, handler).font(font)
```

### Design Philosophy

**Use Regular Font When:**
- The element is meant to be read by users (natural language)
- It's an interactive control label
- It's user-generated content (descriptions, tags, profile names)
- It's explanatory or help text

**Use Monospace Font When:**
- The element provides structure or hierarchy (headers)
- It displays technical data (ports, IPs, protocols)
- It shows status or metadata (badges, counters)
- It's code or configuration syntax
- You want to emphasize technical nature or precision

### Common Patterns

**Sidebar elements:**
```rust
// Section header - MONO
text("PROFILE").size(9).font(state.font_mono).color(theme.fg_muted)

// Status badge - MONO
text("Unsaved Changes*").size(9).font(state.font_mono).color(theme.warning)

// User input - REGULAR
text_input("Search rules...", &state.rule_search).font(state.font_regular)

// User-created tags - REGULAR
button(text(tag.as_str()).size(10).font(state.font_regular))
```

**Form elements:**
```rust
// Form field label - REGULAR
text("DESCRIPTION").size(10).font(regular_font).color(theme.fg_muted)

// Text input for description - REGULAR
text_input("e.g. Local Web Server", &form.label).font(regular_font)

// Technical input - MONO
text_input("80", &form.port_start).font(mono_font)

// Port range separator - MONO
text("-").size(16).font(mono_font)

// Not applicable placeholder - REGULAR (it's a message, not data)
text("Not applicable").font(regular_font).color(theme.fg_muted)
```

**Buttons:**
```rust
// Action button - REGULAR
button(text("Save").size(14).font(regular_font))

// UI button - REGULAR
button(text("Cancel").size(14).font(regular_font))

// Delete button - REGULAR
button(text("×").size(14).font(regular_font))
```

### Implementation Notes

- **200+ font assignments:** Nearly all UI text elements explicitly set fonts
- **No default font inheritance:** Iced's `Settings.default_font` only applies at startup and cannot change dynamically
- **Performance impact:** Negligible - fonts are lightweight references, not copies
- **Visual hierarchy:** Monospace headers create clear structural separation from regular UI text

---

## 6. Modal Windows

**All modals use `card_container(theme)`:**

```rust
container(content)
    .style(|_| card_container(theme))
```

**Provides:**
- Rounded corners (8px radius)
- Crisp shadow (offset: (0.0, 2.0), blur: 3.0)
- Subtle border (1px, `theme.border`)
- Surface background (`theme.bg_surface`)

### Warning Modals
```rust
let mut style = card_container(theme);
style.border = Border {
    color: theme.danger,
    width: 2.0,
    radius: 8.0.into(),  // MUST preserve rounded corners
};
```

**Never use `..Default::default()`** for border—it resets radius to 0.

### Scrolling Dialog Bodies
A dialog whose body can grow (warning blocks, long lists) wraps it in
`scrollable_body()` (`src/app/view/confirmation.rs`, used by the "Commit Changes?" and
Save to System dialogs): a shrink-to-fit scrollable (embedded scrollbar,
`Scrollbar::new().spacing(0)`, 12px right padding) inside a container capped at
`DIALOG_BODY_MAX_HEIGHT` (420px), so the body scrolls and the buttons below it stay on
screen in the default 700px window. Keep the buttons outside the scrollable.

### Layer Order
`view::LAYERS` is the draw order of all dialogs, bottom to top, and must
agree with `handlers::top_layer()` (what Escape, Enter and Tab act on); a
test checks it. Notification banners are the last layer, so no dialog hides
an error. Banners carry a severity word (OK/INFO/WARNING/ERROR) besides the
color, and diff lines a "+"/"-" marker, so nothing relies on color alone.

---

## 7. Dropdown Menus (Pick Lists)

**Location:** `src/app/ui_components.rs` (`themed_pick_list()`, `themed_pick_list_menu()`)

### Control States
```rust
// Active (closed)
background: bg_elevated, border: 1px border

// Hovered
background: bg_hover, border: 1px border_strong

// Opened (depressed effect)
background: bg_base, border: transparent  // Control recedes
```

### Dropdown Menu
```rust
// Brighter than control for separation
let menu_bg = if theme.is_light() {
    bg_elevated * 0.97 + 0.03  // Blend toward white
} else {
    bg_elevated * 1.15 + 0.04  // Hybrid brighten + boost
};

// Borderless with crisp shadow
background: menu_bg,
border: transparent,
shadow: Shadow { offset: (0.0, 2.0), blur: 3.0 }
```

---

## 8. Floating Tooltips

**Location:** `src/app/ui_components.rs:popup_container()`

```rust
container(tooltip_content)
    .style(|_| popup_container(theme))
```

**Provides:**
- Lighter background than `bg_surface` (15% brighter)
- Faded border (15% opacity)
- Tight radius (6px vs 8px for modals)
- Standard delay: 1.0 second (1000ms)

---

## 9. Performance in Views

The rule (never compute in `view()`, cache in `update()`) and the debounce/autosave rules
are in CLAUDE.md §8. The UI-specific patterns:

### Cached Display Strings
Per-rule display text is built once per data change in `Rule::rebuild_caches()`
(`#[serde(skip)]` fields such as `port_display`, `sources_display`, `action_display`
("D (5/s)" / "A"), `interface_display` ("@eth0" / "Any"), `badge_display`); `view()`
only borrows them:
```rust
text(&rule.action_display)               // ✅ borrowed, no allocation
text(format!("{}", rule.action))         // ❌ allocates every frame
```

### Other View Caches
- **Search:** the lowercase search term is stored once per keystroke
  (`rule_search_lowercase`, the pickers' `search_lowercase`); rules carry lowercase
  copies of their fields
- **Collections:** tags, filtered rule lists and picker results are built in `update()`
  (see §13 for the pickers)
- **Syntax:** the ruleset preview and diff are tokenized once per change
  (`cached_nft_tokens`, `cached_diff_tokens`) with their widths (§11)
- **Fonts:** the system font list and its names are built once per process (`OnceLock`
  statics in `src/fonts.rs`, `fonts::all_options()`)
- **One-off formatting:** a constant label is `"Any".into()`, not `"Any".to_string()`;
  a number formatted in `view()` belongs in a cached string field

---

## 10. Gradients & Hybrid Calculations

### Vertical Gradients
```rust
// Use for non-interactive containers only (no shadows needed)
Gradient::Linear(Linear::new(std::f32::consts::PI)  // 0° = vertical
    .add_stop(0.0, top_color)
    .add_stop(1.0, bottom_color))
```

### Hybrid Darkening/Brightening
Very dark themes need additive boost (multiplicative alone is imperceptible):

```rust
if theme.is_light() {
    Color { r: base.r * 0.92, .. }  // Darken: multiply only (8%)
} else {
    Color { r: (base.r * 1.15) + 0.02, .. }  // Brighten: multiply + boost
}
```

**Why:** Ayu Dark's near-black backgrounds require additive component for visibility.

**Centralized:** Use `inset_container(theme)` from `ui_components.rs` instead of inline calculations. This pattern is used for recessed areas like tag clouds and list containers.

---

## 11. Dynamic Horizontal Scrolling

**Location:** width calculation in `src/app/helpers/caching.rs`
(`calculate_max_content_width*`), selection in `preview_content()` (`src/app/view/mod.rs`)

### View-Specific Widths
```rust
pub struct State {
    cached_nft_width_px: f32,   // Ruleset view (active rules only)
    cached_diff_width_px: f32,  // Diff view (includes disabled, plus the "+"/"-" gutter)
}

// The Ruleset tab shows the diff when it is on and there are changes
match (state.show_diff, &state.cached_diff_tokens) {
    (true, Some(diff)) => /* diff tokens */ state.cached_diff_width_px,
    _ => /* ruleset tokens */ state.cached_nft_width_px,
}
```

### Calculation
```rust
const CHAR_WIDTH_PX: f32 = 8.8;   // errs wide: too wide is blank space, too narrow clips
const LINE_NUMBER_WIDTH_PX: f32 = 50.0;
const TRAILING_PADDING_PX: f32 = 60.0;  // ~7 chars breathing room
const MIN_WIDTH_PX: f32 = 800.0;
const MAX_WIDTH_PX: f32 = 40_000.0;  // guards absurd widths only

let max_chars = tokens.iter()
    .map(|line| line.indent + line.tokens.iter().map(|t| t.text.chars().count()).sum())
    .max().unwrap_or(0);
// The diff view adds `view::DIFF_GUTTER_WIDTH_PX` for its "+"/"-" markers

let width = (LINE_NUMBER_WIDTH_PX + (max_chars as f32 * CHAR_WIDTH_PX) + TRAILING_PADDING_PX)
    .clamp(MIN_WIDTH_PX, MAX_WIDTH_PX);
```

**Why layout shifts are acceptable:** User explicitly changes views (tab switch, diff toggle).

---

## 12. Inset Progress Bar

**Location:** `build_confirmation_body()` in `src/app/view/confirmation.rs` (the
auto-revert countdown)

### Two-Layer Structure
```rust
container(  // Outer rim (recessed groove)
    progress_bar(0.0..=1.0, progress)  // Inner fill
        .style(|_| /* fill styling */)
)
.padding(Padding {
    top: 2.5,    // Asymmetric for depth perception
    right: 2.0,
    bottom: 1.0,
    left: 2.0,
})
.style(|_| /* rim styling */)
```

### Rim Styling
```rust
// Negative Y offset creates top shadow (inset illusion)
shadow: Shadow {
    color: bg_surface * 0.5 @ 0.9 alpha,
    offset: (0.0, -1.0),  // NEGATIVE = inset
    blur_radius: 1.0,
}

// Vertical gradient for depth
let (rim_top, rim_bottom) = if theme.is_light() {
    (0.5, 0.95)  // 50% darker top, 5% darker bottom
} else {
    (0.5, 0.88)  // 50% darker top, 12% darker bottom
};
```

### Fill Colors
**Dark themes:** Colored fill (accent → danger at 5s), darkened 15%
**Light themes:** Gray fill (70% → 65% at 5s for urgency)

### Animation
```rust
// Linear animation from full to empty over the guard's timeout (handlers/apply.rs)
state.progress_animation = iced::Animation::new(1.0)
    .easing(iced::animation::Easing::Linear)
    .duration(timeout)
    .go(0.0, iced::time::Instant::now());
```
The view interpolates it on every redraw; the only timer while the countdown runs is
the 1-second `CountdownTick` subscription (the number changes once per second; so does
the bar). Do not add a frame-rate subscription: every tick rebuilds the whole view.

---

## 13. Theme Picker Patterns

### Modal Width
**Use comfortable width with slack, not exact calculations:**

```rust
// view_theme_picker() in src/app/view/pickers.rs
const CARD_WIDTH: f32 = 150.0;
const CARD_SPACING: f32 = 10.0;
const GRID_PADDING: f32 = 10.0;
const MODAL_WIDTH: f32 = 548.0;  // Fine-tuned (not calculated)
```

**Rule:** Choose width, add ~24px slack for scrollbar, fine-tune ±10px visually.

### Performance
**Filter in `update()`, never in `view()`:** `ThemePickerState` / `FontPickerState`
keep the filtered index list and count label, recomputed by `refilter()` only when
the search text changes. `view()` just iterates the cached indices; converted
`AppTheme`s are cached the same way (`ThemePickerState::cached_themes`).

---

## 14. Border Radius Guidelines

- **8.0px:** Modals, cards, primary buttons (soft, interactive)
- **6.0px:** Tooltips, inner progress bars (nested elements)
- **4.0px:** Section headers, secondary buttons
- **0.0px:** Tabs, structural containers (visual distinction)
- **12.0+px:** Tag pills, badges (token elements)

---

## 15. Key Files Reference

- **`src/theme/mod.rs`** - Theme struct, shadow/gradient calculations
- **`src/theme/presets.rs`** - Built-in theme definitions
- **`src/app/ui_components.rs`** - All button/container style functions
- **`src/app/view/`** - View rendering, one file per panel or dialog (`mod.rs` holds the
  layer order and the ruleset preview)
- **`src/app/helpers/`** - Pure helpers for cached widths, filtering and formatting

---

## 16. Common Mistakes

### ❌ Don't
- Implement `Catalog` traits for `AppTheme`
- Use gradients on interactive elements (breaks shadows)
- Create inline button styles or duplicate button functions
- Use `..Default::default()` for borders (resets radius)
- Compute expensive operations in `view()` (e.g., `format!()`, `.to_string()`)
- Use hardcoded RGB colors
- Forget to set `.font()` on text widgets (won't respect user font choice)
- Use monospace for user-facing explanatory text

### ✅ Do
- Use centralized style functions from `ui_components.rs`
- Use semantic color names from theme
- Cache computed/formatted strings in struct fields (`#[serde(skip)]`)
- Pre-compute display strings in `rebuild_caches()` or `update()`
- Preserve rounded corners on warning modals
- Test across multiple themes (light and dark)
- Pre-allocate collections when size is known
- Set `.font()` explicitly on all text, inputs, buttons, checkboxes, and dropdowns
- Use `font_regular` for UI controls, `font_mono` for technical/structural elements

---

## 17. Scrollbar Patterns

**Problem:** By default, scrollbars overlay content, potentially obscuring cards/list items.

### Pattern 1: Borderless Scrollable (Preferred)
Use when the scrollable area has **no visible border** (e.g., sidebar lists).

```rust
scrollable(container(content).width(Length::Fill))
    .direction(scrollable::Direction::Vertical(
        scrollable::Scrollbar::new().spacing(8),
    ))
    .style(move |_, status| themed_scrollable(theme, status))
```

**Key Details:**
- **`Scrollbar::new().spacing(8)`** creates gap between content and scrollbar
- **Scrollbar only appears when needed** - content stays symmetrical when no scrollbar
- **No content padding required** - the spacing handles the gap automatically
- **Result:** Clean, symmetrical layout that adapts to content size

**Applied Locations:**
- Sidebar tag cloud (sidebar.rs)
- Sidebar rule list (sidebar.rs)

### Pattern 2: Bordered Scrollable
Use when the scrollable area has a **visible border** (e.g., modals with bordered containers).

```rust
scrollable(
    container(content)
        .width(Length::Fill)
        .padding(8),  // Symmetric padding for breathing room from border
)
.direction(scrollable::Direction::Vertical(
    scrollable::Scrollbar::new().spacing(0),
))
.style(move |_, status| themed_scrollable(theme, status))
```

**Key Details:**
- **`Scrollbar::new().spacing(0)`** enables embedded mode with no extra gap
- **Symmetric `.padding(8)`** keeps content away from border edges on all sides
- **Required because:** Border creates visual boundary; content touching it looks cramped
- **Result:** Content has consistent breathing room from bordered container

**Applied Locations:**
- Profile Manager modal (`view_profile_manager()` in `profile.rs`)
- Theme and Font Picker modals (`pickers.rs`)
- Dialog bodies via `scrollable_body()` (`confirmation.rs`, §6)

