# DRFW UI Style Guide

This document outlines the UI design decisions and styling patterns used in the Dumb Rust Firewall application. It serves as a reference for maintaining visual consistency across future development.

## Design Philosophy

### Core Principles
- **Clarity over decoration**: UI elements should be functional first, stylish second
- **Theme awareness**: All styling adapts intelligently to light/dark themes
- **Subtle depth**: Use shadows and gradients sparingly to establish hierarchy
- **Performance first**: Avoid techniques that hurt rendering performance (gradients break shadows in Iced)

### Semantic Color System

Colors are defined semantically in `src/theme/mod.rs`:

```rust
pub struct AppTheme {
    // Background layers (progressive depth)
    pub bg_base: Color,     // App background (deepest)
    pub bg_sidebar: Color,  // Sidebar background
    pub bg_surface: Color,  // Cards, containers
    pub bg_elevated: Color, // Inputs, buttons
    pub bg_hover: Color,    // Hover states
    pub bg_active: Color,   // Active/selected states

    // Foreground/Text
    pub fg_primary: Color,   // Main text
    pub fg_secondary: Color, // Less important text
    pub fg_muted: Color,     // Disabled/placeholder
    pub fg_on_accent: Color, // Text on accent colors

    // Semantic colors
    pub accent: Color,
    pub success: Color,
    pub warning: Color,
    pub danger: Color,
    // ... etc
}
```

**Why semantic naming?** Instead of `button_bg` or `input_color`, we use progressive background layers (`bg_base` → `bg_surface` → `bg_elevated`) that automatically work across all themes.

---

## Shadow System

### Implementation
**Location:** `src/theme/mod.rs:86-99`

Shadows use theme-aware opacity for consistent depth perception:

```rust
let (shadow_color, shadow_strong) = if is_light {
    // Light themes: crisp and visible without muddiness (35%)
    (
        Color::from_rgba(0.0, 0.0, 0.0, 0.35),
        Color::from_rgba(0.0, 0.0, 0.0, 0.5),
    )
} else {
    // Dark themes: stronger for pixel-perfect depth (60%)
    (
        Color::from_rgba(0.0, 0.0, 0.0, 0.6),
        Color::from_rgba(0.0, 0.0, 0.0, 0.85),
    )
};
```

### Shadow Usage Patterns

**Button shadows** (subtle elevation):
```rust
shadow: Shadow {
    color: theme.shadow_color,
    offset: Vector::new(0.0, 2.0),
    blur_radius: 4.0,
}
```

**Hover state** (increased elevation):
```rust
offset: Vector::new(0.0, 3.0),
blur_radius: 6.0,
```

**Pressed state** (reduced elevation):
```rust
offset: Vector::new(0.0, 1.0),
blur_radius: 2.0,
```

### Critical Constraint: Gradients Break Shadows

**Issue:** In Iced 0.14, using gradient backgrounds causes shadow rendering to fail completely.

**Solution:** When using gradients, set `shadow: Shadow::default()` (no shadow). This is why we reverted gradient active tabs - the shadow provides important visual feedback.

**Reference:** Commit dfb6884 reverted gradient tabs due to this limitation.

---

## Gradient System

### Implementation
**Location:** `src/app/ui_components.rs` (sidebar/workspace containers)

Gradients are used sparingly for background containers, not interactive elements (due to shadow constraint).

### Hybrid Approach for Dark Themes

Very dark themes (like Ayu Dark) have a problem: multiplicative gradients (`color * 1.2`) on near-black backgrounds produce imperceptible changes.

**Solution:** Hybrid formula combining multiplication and addition:
```rust
if theme.is_light() {
    // Light: darken with multiplication only
    Color {
        r: (base.r * 0.8).max(0.0),
        g: (base.g * 0.8).max(0.0),
        b: (base.b * 0.8).max(0.0),
        ..base
    }
} else {
    // Dark: brighten with multiplication + small boost
    Color {
        r: ((base.r * 1.4) + 0.03).min(1.0),
        g: ((base.g * 1.4) + 0.03).min(1.0),
        b: ((base.b * 1.4) + 0.03).min(1.0),
        ..base
    }
}
```

The `+ 0.03` additive boost ensures visibility even on very dark backgrounds.

**Gradient angle:** `0.0` = vertical (top to bottom)

---

## Button Styling

### Button Categories

We have distinct button styles for different purposes:

1. **Primary buttons** - Main actions (Apply, Save)
   - Background: `theme.accent`
   - Text: `theme.fg_on_accent`
   - Prominent accent color

2. **Secondary buttons** - Supporting actions (Cancel, Export, Diagnostics)
   - Background: `theme.bg_surface`
   - Border: `theme.border` (1px)
   - Radius: `4.0` (rounded)

3. **Active tab buttons** - Currently selected workspace tab
   - Background: `theme.bg_elevated`
   - Radius: `0.0` (square)
   - Shadow with elevation changes

4. **Inactive tab buttons** - Unselected workspace tabs
   - Background: `theme.bg_surface`
   - Border: `theme.border` (1px)
   - Radius: `0.0` (square)

### Why Separate Tab Button Styles?

**Issue:** We initially used `secondary_button` for inactive tabs. When we made tabs square (`radius: 0.0`), it affected Export/Diagnostics buttons too.

**Solution:** Created dedicated `active_tab_button` and `inactive_tab_button` styles in `src/app/ui_components.rs:364-449`.

**Result:** Tab buttons are square for visual distinction, while utility buttons remain rounded.

---

## Tab Strip Design

### Current Implementation
**Location:** `src/app/view.rs:865-883` (tab button rendering)

### Design Goals
1. Make the tab strip visually distinct from other UI elements
2. Clearly indicate which tab is active
3. Keep performance high (avoid wrapper containers)

### Evolution

**Attempt 1: Container Wrappers with Accent Top Border**
- Wrapped each tab in a container with 3px top padding
- Active tab container had accent background (creating colored top bar)
- **Result:** 3 buttons → 6 elements (100% overhead), alignment bugs, complexity
- **Status:** Rejected for performance and maintainability

**Attempt 2: Square Tabs with Solid Backgrounds**
- Changed tab radius from `4.0` to `0.0` (square corners)
- Active: `bg_elevated` with shadow elevation feedback
- Inactive: `bg_surface` with `border` (1px)
- **Result:** Clean, performant, visually distinct
- **Status:** ✅ Current implementation (commit dfb6884)

### Square Tab Design
```rust
// Active tab
border: Border {
    radius: 0.0.into(),  // Square
    ..Default::default()
},
background: Some(theme.bg_elevated.into()),

// Inactive tab
border: Border {
    color: theme.border,
    width: 1.0,
    radius: 0.0.into(),  // Square
},
background: Some(theme.bg_surface.into()),
```

**Tab strip container** also square:
```rust
.style(move |_| container::Style {
    background: Some(theme.bg_elevated.into()),
    border: Border {
        radius: 0.0.into(),  // Square container
        ..Default::default()
    },
    ..Default::default()
})
```

### Why Square?

Square tabs create visual distinction from rounded UI elements (cards, secondary buttons, inputs). The sharp corners signal "this is a navigation element" rather than "this is an action button."

---

## What We Rejected and Why

### 1. Implementing Catalog Traits for Custom Theme
**Attempted:** Implementing `button::Catalog`, `container::Catalog`, etc. on `AppTheme`
**Result:** 168 compiler errors about ambiguous associated types
**Why it failed:** Catalog traits are for widget library authors, not application developers
**Correct approach:** Use closure-based styling: `.style(|theme, status| { ... })`
**Reference:** See CLAUDE.md Section 9

### 2. Gradient Active Tabs
**Attempted:** Vertical gradient on active tab using `theme.accent`
**Result:** Shadow rendering broke (Iced limitation)
**Why it failed:** Gradients and shadows are mutually exclusive in Iced 0.14
**Status:** Deferred for future consideration
**Note:** If shadows can be sacrificed, gradient code pattern is preserved in git history

### 3. Container Wrapper Pattern for Top-Only Borders
**Attempted:** Wrapping tabs in containers with colored padding to fake top-border
**Result:** Performance overhead (2x elements), alignment bugs, maintenance complexity
**Why it failed:** Violated "minimum complexity" principle from CLAUDE.md
**Alternative:** Use simple background color differences and borders

### 4. Over-Engineering Hover Effects
**Attempted:** Calculating hover colors from base with complex formulas
**Result:** Inconsistent feel, "awkward" transitions
**Solution:** Use `theme.bg_hover` directly - it's already designed for this

---

## Performance Considerations

### Widget Creation in view()

Iced calls `view()` at 30-60 FPS. **Never** do expensive work here.

**Bad:**
```rust
pub fn view(&self) -> Element {
    let highlighted = syntax_highlight(&self.text); // Runs 60 times/sec!
    container(highlighted).into()
}
```

**Good:**
```rust
fn update(&mut self, msg: Message) {
    self.cached_highlighted = syntax_highlight(&self.text); // Once per change
}

pub fn view(&self) -> Element {
    container(&self.cached_highlighted).into() // Just reference
}
```

### Current Optimizations Applied

1. **Font names cached** - Single static allocation vs 100+ individual leaks (Phase 2)
2. **Tag collection pre-computed** - Sorted/deduped in `update()`, not `view()` (Phase 3)
3. **Lowercase search cached** - `.to_lowercase()` once per keystroke, not per frame (Phase 4)
4. **Pre-allocated collections** - `Vec::with_capacity()` prevents reallocations (Phase 5)

**Reference:** See CLAUDE.md Section 10 for detailed performance patterns

---

## Styling Best Practices

### 1. Theme-Aware Calculations

Always check `theme.is_light()` when computing derived colors:

```rust
let hover_color = if theme.is_light() {
    // Light: darken on hover
    Color { r: base.r * 0.9, /* ... */ }
} else {
    // Dark: brighten on hover
    Color { r: base.r * 1.1, /* ... */ }
};
```

### 2. Use Semantic Colors

**Bad:**
```rust
background: Some(Color::from_rgb(0.2, 0.2, 0.2).into())
```

**Good:**
```rust
background: Some(theme.bg_surface.into())
```

Semantic colors automatically adapt to theme changes.

### 3. Shadow Feedback Pattern

Interactive elements should provide tactile feedback via shadow elevation:
- **Rest:** `offset: (0.0, 2.0), blur: 4.0`
- **Hover:** `offset: (0.0, 3.0), blur: 6.0` (higher)
- **Pressed:** `offset: (0.0, 1.0), blur: 2.0` (lower)

This mimics physical buttons rising on hover and compressing on press.

### 4. Border Radius Guidelines

- **Rounded (4.0):** Action buttons, inputs, cards - "soft" interactive elements
- **Square (0.0):** Navigation tabs, containers - "structural" UI elements
- **Very rounded (8.0+):** Tag pills, badges - "token" elements

### 5. Avoid Premature Abstraction

Don't create helper functions until you have 3+ identical use cases:

**Premature:**
```rust
fn make_button_shadow(theme: &AppTheme, elevation: f32) -> Shadow { /* ... */ }
```

**Better:** Just inline the shadow configuration. If it becomes repetitive, refactor then.

---

## Future Considerations

### Potential Enhancements

1. **Gradient Active Tabs** - Revisit if Iced adds gradient+shadow support
   - Would use `accent` color with subtle vertical gradient
   - Pattern preserved in git history before dfb6884

2. **Animated Transitions** - Smooth color transitions on hover/press
   - Requires Iced animation support
   - Low priority (subtle is better)

3. **Custom Focus Indicators** - Accessibility improvement
   - Add visible focus rings for keyboard navigation
   - Use `theme.accent` with reduced opacity

### Adding New Themes

When adding themes to `src/theme/presets.rs`:

1. Test with very dark backgrounds (like Ayu Dark) to ensure gradients are visible
2. Verify shadow opacity works (35% light, 60% dark is baseline)
3. Check `fg_on_accent` has sufficient contrast (WCAG AA minimum)
4. Test all button states (hover, pressed, disabled)

### Modifying Existing Styles

Before changing a style function:
1. Check if it's used for multiple purposes (tabs AND buttons?)
2. Create a new style function rather than changing behavior
3. Update this document with the reasoning
4. Test across multiple themes (light and dark)

---

## Reference: Key Files

- **`src/theme/mod.rs`** - Theme struct, shadow calculation, luminance detection
- **`src/theme/presets.rs`** - All built-in theme definitions
- **`src/app/ui_components.rs`** - All button/container style functions
- **`src/app/view.rs`** - View rendering, tab button implementation

---

## Changelog

### 2025-12-27
- **Tab Strip Redesign:** Made tabs square (radius 0.0) for visual distinction
- **Separated Tab Styles:** Created `inactive_tab_button` separate from `secondary_button`
- **Gradient Experiment:** Tried gradient active tabs, reverted due to shadow incompatibility
- **Document Created:** Initial style guide documenting design decisions

---

**Document Version:** 1.0
**Last Updated:** 2025-12-27
**Iced Version:** 0.14
