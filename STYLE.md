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

**Location:** `src/theme/mod.rs:94-99`

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
```

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
.padding([8, 16]).size(13)   // nftables.conf, JSON, Settings

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
- Code/configuration previews (nftables, JSON)
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

---

## 7. Dropdown Menus (Pick Lists)

**Location:** `src/app/ui_components.rs:themed_pick_list()`

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

### Height Limiting
**Selective application:** Only apply `.menu_height(300.0)` to dropdowns with many items (Service Presets).

**Never apply to short dropdowns** (Protocol, Interface) — Iced's `menu_height()` sets fixed height, not maximum.

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

## 9. Performance Requirements

### Cache in update(), Reference in view()
```rust
// ❌ BAD - Runs 60 times/second
pub fn view(&self) -> Element {
    let highlighted = compute_expensive_thing();  // NEVER
}

// ✅ GOOD - Compute once on change
fn update(&mut self, msg: Message) {
    self.cached_result = compute_expensive_thing();
}

pub fn view(&self) -> Element {
    container(&self.cached_result)  // Just reference
}
```

### Applied Optimizations
- **Lowercase search:** Cache `.to_lowercase()` once per keystroke
- **Tag collections:** Pre-sort/dedupe in `update()`
- **Syntax tokens:** Cache highlighted lines
- **Font names:** Single static allocation vs 100+ leaks

**Reference:** See CLAUDE.md Section 8 for detailed patterns.

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

**Location:** `src/app/mod.rs:353-399`

### View-Specific Widths
```rust
pub struct State {
    cached_nft_width_px: f32,   // NFT view (active rules only)
    cached_json_width_px: f32,  // JSON view
    cached_diff_width_px: f32,  // Diff view (includes disabled)
}

// Select based on current tab/diff state
let content_width = match (state.active_tab, state.show_diff) {
    (WorkspaceTab::Nftables, true) => state.cached_diff_width_px,
    (WorkspaceTab::Nftables, false) => state.cached_nft_width_px,
    (WorkspaceTab::Json, _) => state.cached_json_width_px,
    _ => state.cached_nft_width_px,
};
```

### Calculation
```rust
const CHAR_WIDTH_PX: f32 = 8.4;
const LINE_NUMBER_WIDTH_PX: f32 = 50.0;
const TRAILING_PADDING_PX: f32 = 60.0;  // ~7 chars breathing room
const MIN_WIDTH_PX: f32 = 800.0;
const MAX_WIDTH_PX: f32 = 3000.0;

let max_chars = tokens.iter()
    .map(|line| line.indent + line.tokens.iter().map(|t| t.text.len()).sum())
    .max().unwrap_or(0);

let width = (LINE_NUMBER_WIDTH_PX + (max_chars as f32 * CHAR_WIDTH_PX) + TRAILING_PADDING_PX)
    .clamp(MIN_WIDTH_PX, MAX_WIDTH_PX);
```

**Why layout shifts are acceptable:** User explicitly changes views (tab switch, diff toggle).

---

## 12. Inset Progress Bar

**Location:** `src/app/view.rs:1790-1920`

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

### Smooth Animation
```rust
// 60 FPS linear animation
self.progress_animation = Animation::new(1.0)
    .easing(animation::Easing::Linear)  // Constant speed
    .duration(Duration::from_secs(timeout))
    .go(0.0, iced::time::Instant::now());

// Subscription for frame updates
iced::time::every(Duration::from_millis(17))  // ~60 FPS
```

---

## 13. Theme Picker Patterns

### Modal Width
**Use comfortable width with slack, not exact calculations:**

```rust
const CARD_WIDTH: f32 = 150.0;
const CARD_SPACING: f32 = 16.0;
const GRID_PADDING: f32 = 8.0;
const MODAL_WIDTH: f32 = 556.0;  // Fine-tuned (not calculated)
```

**Rule:** Choose width, add ~24px slack for scrollbar, fine-tune ±10px visually.

### Performance
**Cache theme conversions:**
```rust
let filtered_themes: Vec<(ThemeChoice, AppTheme)> = ThemeChoice::all()
    .filter_map(|choice| {
        let theme = choice.to_theme();  // Cache this!
        Some((*choice, theme))
    })
    .collect();
```

**Use ASCII-only search:** `to_ascii_lowercase()` vs `to_lowercase()` (theme names are ASCII).

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
- **`src/app/view.rs`** - View rendering, widget usage

---

## 16. Common Mistakes

### ❌ Don't
- Implement `Catalog` traits for `AppTheme`
- Use gradients on interactive elements (breaks shadows)
- Create inline button styles or duplicate button functions
- Use `..Default::default()` for borders (resets radius)
- Apply fixed `menu_height()` to short dropdowns
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
- Profile Manager modal (profile.rs:196-208)
- Font Picker modal (pickers.rs)

---

**Last Updated:** 2026-01-09 (Added container style functions, removed shadow_strong, updated hybrid calculations)
**DRFW Version:** 0.9.0
**Iced Version:** 0.14
