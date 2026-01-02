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
    shadow_color: Color, shadow_strong: Color,

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

**Location:** `src/theme/mod.rs:86-99`

### Shadow Values
```rust
// Light themes
shadow_color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),
shadow_strong: Color::from_rgba(0.0, 0.0, 0.0, 0.5),

// Dark themes
shadow_color: Color::from_rgba(0.0, 0.0, 0.0, 0.6),
shadow_strong: Color::from_rgba(0.0, 0.0, 0.0, 0.85),
```

### Elevation Patterns
**Buttons:**
- Rest: `offset: (0.0, 2.0), blur: 4.0`
- Hover: `offset: (0.0, 3.0), blur: 6.0`
- Pressed: `offset: (0.0, 1.0), blur: 2.0`

**Modals/Tooltips:**
- Standard: `offset: (0.0, 2.0), blur: 3.0`
- Use `shadow_color`, never `shadow_strong` for modals

### Critical Constraint
**Gradients break shadows in Iced 0.14.** Interactive elements must choose one:
- Use gradients → no shadow
- Use shadows → solid backgrounds only

This is why tabs use solid backgrounds instead of gradients.

---

## 3. Centralized Button Styles

**Location:** `src/app/ui_components.rs`

### Style Functions
```rust
primary_button(theme, status)       // Main actions (Apply, Save)
secondary_button(theme, status)     // Supporting actions (Cancel, Export)
danger_button(theme, status)        // Destructive actions (Delete, Rollback)
card_button(theme, status)          // Large clickable cards (export options)
active_tab_button(theme, status)    // Selected tabs
inactive_tab_button(theme, status)  // Unselected tabs
dirty_button(theme, status)         // Unsaved changes indicator
```

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

## 5. Modal Windows

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

## 6. Dropdown Menus (Pick Lists)

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

## 7. Floating Tooltips

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

## 8. Performance Requirements

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

## 9. Gradients & Hybrid Calculations

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
    Color { r: base.r * 0.8, .. }  // Darken: multiply only
} else {
    Color { r: (base.r * 1.4) + 0.03, .. }  // Brighten: multiply + boost
}
```

**Why:** Ayu Dark's near-black backgrounds require additive component for visibility.

---

## 10. Dynamic Horizontal Scrolling

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

## 11. Inset Progress Bar

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

## 12. Theme Picker Patterns

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

## 13. Border Radius Guidelines

- **8.0px:** Modals, cards, primary buttons (soft, interactive)
- **6.0px:** Tooltips, inner progress bars (nested elements)
- **4.0px:** Section headers, secondary buttons
- **0.0px:** Tabs, structural containers (visual distinction)
- **12.0+px:** Tag pills, badges (token elements)

---

## 14. Key Files Reference

- **`src/theme/mod.rs`** - Theme struct, shadow/gradient calculations
- **`src/theme/presets.rs`** - Built-in theme definitions
- **`src/app/ui_components.rs`** - All button/container style functions
- **`src/app/view.rs`** - View rendering, widget usage

---

## 15. Common Mistakes

### ❌ Don't
- Implement `Catalog` traits for `AppTheme`
- Use gradients on interactive elements (breaks shadows)
- Create inline button styles
- Use `..Default::default()` for borders (resets radius)
- Apply fixed `menu_height()` to short dropdowns
- Compute expensive operations in `view()`
- Use hardcoded RGB colors

### ✅ Do
- Use centralized style functions
- Use semantic color names
- Cache computed data in `update()`
- Preserve rounded corners on warning modals
- Test across multiple themes (light and dark)
- Pre-allocate collections when size is known

---

**Last Updated:** 2026-01-02
**DRFW Version:** 0.1.0
**Iced Version:** 0.14
