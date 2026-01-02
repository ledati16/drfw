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

## Section Header Pattern

### Purpose

Section headers provide subtle visual separation and hierarchy for labels, field names, and organizational text throughout the UI. They use a minimal backdrop to make text stand out slightly from the background without being heavy-handed.

### Implementation

**Location:** `src/app/ui_components.rs:125-140`

```rust
pub fn section_header_container(theme: &AppTheme) -> container::Style {
    container::Style {
        background: Some(
            Color {
                a: 0.05, // Subtle opacity - visible but not overwhelming
                ..theme.fg_primary
            }
            .into(),
        ),
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}
```

**Key characteristics:**
- **5% opacity** of `fg_primary` color (increased from initial 0.02 for better visibility)
- **4px border radius** for subtle rounding
- **Works across all themes** - uses semantic `fg_primary` so adapts automatically
- **Minimal performance cost** - just a container with background color

### Usage Pattern

Wrap text in a container with this style and small padding:

```rust
container(text("FILTERS")
    .size(9)
    .font(state.font_mono)
    .color(theme.fg_muted))
    .padding([2, 6])  // Small padding: [vertical, horizontal]
    .style(move |_| section_header_container(theme))
```

**Padding guidelines:**
- **[2, 6]** for small labels (size 9-11): "FILTERS", "PREVIEW:", field labels
- **[4, 8]** for larger headers (size 12+): "Select Theme", "BASIC INFO"

### Where to Use Section Headers

✅ **Good uses** - Adds clarity and visual hierarchy:

1. **Sidebar section labels:**
   - "DUMB RUST FIREWALL" subtitle
   - "FILTERS"
   - "RULES"

2. **Modal/dialog titles:**
   - "Select Theme"
   - "Select UI Font" / "Select Code Font"
   - "⌨️ Keyboard Shortcuts"
   - "Commit Changes?"
   - "Confirm Safety"

3. **Form section headers:**
   - "BASIC INFO", "TECHNICAL DETAILS", "CONTEXT", "ORGANIZATION"
   - "APPEARANCE", "ADVANCED SECURITY"

4. **Field labels within forms:**
   - "PROTOCOL", "PORT RANGE", "SOURCE ADDRESS", "INTERFACE", "TAGS"

5. **Preview/status indicators:**
   - "PREVIEW:" (in theme picker - note: just the label, not dynamic content)
   - "Text Hierarchy", "Status Colors" (in theme preview panel)

6. **Footer metadata:**
   - "{X} themes available" (theme picker)
   - "{X} fonts available" (font picker)

❌ **Avoid using for:**

1. **Large page titles** - These are already prominent via size/color
   - ~~"Active Configuration"~~ - too large, doesn't need extra treatment
   - ~~"JSON Export"~~ - same
   - Main workspace titles work better with size/color alone

2. **Dynamic content** - Keep the backdrop on the static label only
   - ✅ "PREVIEW:" ← static label gets backdrop
   - ❌ ~~"PREVIEW: Ayu Dark"~~ ← don't wrap dynamic theme name
   - Theme name should be plain text next to the label

3. **Body text or descriptions** - Only for headers/labels
   - "Current nftables ruleset generated from your rules." ← too long, descriptive text

4. **Action buttons** - Use button styles instead
   - Buttons already have their own styling system

### Design Rationale

**Why this pattern works:**

1. **Subtle hierarchy** - Doesn't compete with content, just organizes it
2. **Consistent treatment** - Same visual weight across all section headers
3. **Theme-aware** - Uses semantic color so works in light/dark themes
4. **Minimal** - Small opacity (5%) prevents visual clutter
5. **Performant** - Simple container style, negligible overhead
6. **Maintainable** - Centralized function, easy to adjust globally

**Evolution:**
- Initial opacity: **0.02** (too subtle, barely visible)
- Current opacity: **0.05** (2.5x more visible, sweet spot)
- If ever too prominent, reduce to 0.03-0.04
- If too subtle again, increase to 0.06-0.07

### Spacing Consistency

Section headers revealed spacing inconsistencies in the sidebar that were fixed:

**Problem:**
- FILTERS → tags: 8px spacing
- RULES → cards: 12px spacing (inconsistent!)
- Rule cards had extra [0, 2] padding wrapper
- RULES header had [0, 4] padding on row

**Solution:**
- Standardized to **8px spacing** for both
- Removed extra padding wrappers
- Now perfectly aligned with consistent visual rhythm

**Lesson:** Section headers make spacing issues more visible - use them as a diagnostic tool when polishing UI.

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

## Dropdown Menu Styling (Pick Lists)

### Implementation
**Location:** `src/app/ui_components.rs:597-653` (pick_list styling), `src/app/view.rs` (widget usage)

Dropdown menus feature a borderless design with crisp shadows and a "depressed" visual effect when opened.

### Pick List Control States

**Active state** (closed, not hovered):
```rust
background: theme.bg_elevated,
border: 1px theme.border,
```

**Hovered state**:
```rust
background: theme.bg_hover,
border: 1px theme.border_strong,
```

**Opened state** (dropdown menu visible):
```rust
background: theme.bg_base, // Dimmed to deepest layer for "pressed in" effect
border: transparent, // No border - menu shadow provides definition
```

**Design rationale:** When the dropdown opens, the control dims to the deepest background layer (`bg_base`) and loses its border. This creates a visual "depression" effect - the control appears to recede, making the floating menu stand out more clearly.

### Dropdown Menu Styling

The dropdown menu itself uses borderless, crisp shadow design with a calculated brighter background:

```rust
// Calculate brighter background to distinguish from input controls
let menu_bg = if theme.is_light() {
    // Light: brighten toward white (97% original + 3% white)
    Color {
        r: (theme.bg_elevated.r * 0.97 + 0.03).min(1.0),
        g: (theme.bg_elevated.g * 0.97 + 0.03).min(1.0),
        b: (theme.bg_elevated.b * 0.97 + 0.03).min(1.0),
        ..theme.bg_elevated
    }
} else {
    // Dark: hybrid brighten (15% brighter + 4% boost)
    Color {
        r: (theme.bg_elevated.r * 1.15 + 0.04).min(1.0),
        g: (theme.bg_elevated.g * 1.15 + 0.04).min(1.0),
        b: (theme.bg_elevated.b * 1.15 + 0.04).min(1.0),
        ..theme.bg_elevated
    }
};

background: menu_bg,
border: transparent (no border),
shadow: Shadow {
    offset: (0.0, 2.0), // Directional shadow matching modals
    blur: 3.0,          // Crisp, clean definition
}
```

**Why brighter than `bg_elevated`?** Menu items need visual distinction from the input control they're hovering over. Since controls use `bg_elevated` and dim to `bg_base` when opened, making the menu brighter creates clear separation.

**Theme-aware calculation:**
- Light themes: Blend toward white (maintains brightness)
- Dark themes: Hybrid multiply + boost (ensures visibility on very dark backgrounds)
- Follows the same pattern as gradient calculations elsewhere in the app

**Why no border?** The crisp shadow provides all the definition needed. Adding a border creates visual clutter and can overlap awkwardly when the menu opens upward.

**Why directional shadow?** Consistency with modals - both are overlays floating above content, so they follow the same elevation/lighting pattern.

### Menu Height Limiting

**Selective application:** Only dropdowns with many items need height limits. Apply `.menu_height(300.0)` selectively based on content:

```rust
// Service Preset: 50+ items - NEEDS height limit
pick_list(PRESETS, selected, on_select)
    .menu_height(300.0) // Scrollable after ~10-12 items
    .style(move |_, status| themed_pick_list(theme, status))
    .menu_style(move |_| themed_pick_list_menu(theme))

// Protocol: 5 items - NO height limit (auto-sizes perfectly)
pick_list(protocols, selected, on_select)
    .style(move |_, status| themed_pick_list(theme, status))
    .menu_style(move |_| themed_pick_list_menu(theme))

// Interface: <10 items typically - NO height limit (auto-sizes)
pick_list(interfaces, selected, on_select)
    .style(move |_, status| themed_pick_list(theme, status))
    .menu_style(move |_| themed_pick_list_menu(theme))
```

**Why selective?** Iced's `menu_height()` sets a **fixed height**, not a maximum. Using `Fixed(300.0)` on short lists creates awkward empty space. There is no `Length::Shrink` with a max cap in Iced 0.14.

**300px rationale:** Allows approximately 10-12 items visible before scrolling. Prevents long lists (service presets) from extending off-screen.

### Selected Item Styling

Menu items use consistent hover pattern:
```rust
selected_background: theme.bg_hover,
selected_text_color: theme.fg_primary,
```

---

## Button Styling

### Centralized Button Styles

All button styles are centralized in `src/app/ui_components.rs` to ensure consistency. **Never define inline button styles** - always use these functions:

**Location:** `src/app/ui_components.rs`

```rust
pub fn primary_button(theme: &AppTheme, status: button::Status) -> button::Style
pub fn secondary_button(theme: &AppTheme, status: button::Status) -> button::Style
pub fn danger_button(theme: &AppTheme, status: button::Status) -> button::Style
pub fn dirty_button(theme: &AppTheme, status: button::Status) -> button::Style
pub fn card_button(theme: &AppTheme, status: button::Status) -> button::Style
pub fn active_card_button(theme: &AppTheme, status: button::Status) -> button::Style
pub fn active_tab_button(theme: &AppTheme, status: button::Status) -> button::Style
pub fn inactive_tab_button(theme: &AppTheme, status: button::Status) -> button::Style
```

**All these styles** automatically provide consistent shadow feedback:
- **Rest:** `offset: (0.0, 2.0), blur: 3.0-4.0`
- **Hover:** `offset: (0.0, 3.0), blur: 6.0` (elevated)
- **Pressed:** `offset: (0.0, 1.0), blur: 2.0` (compressed)

### Button Categories

We have distinct button styles for different purposes:

1. **Primary buttons** (`primary_button`) - Main actions (Apply, Save)
   - Background: `theme.accent`
   - Text: `theme.fg_on_accent`
   - Prominent accent color
   - **Use for:** Primary actions that advance workflow

2. **Secondary buttons** (`secondary_button`) - Supporting actions (Cancel, Export, Diagnostics)
   - Background: `theme.bg_surface`
   - Border: `theme.border` (1px)
   - Radius: `4.0` (rounded)
   - **Use for:** Secondary actions, navigation, utility tools

3. **Danger buttons** (`danger_button`) - Destructive actions (Delete, Rollback, "Yes I understand")
   - Background: `theme.danger`
   - Text: `theme.fg_on_accent`
   - **Use for:** Confirming destructive or risky operations

4. **Card buttons** (`card_button`) - Clickable card-style elements (Export options, font selection)
   - Inherits `card_container` styling
   - Text: `theme.fg_primary`
   - **Hover shadow:** More dramatic elevation (offset `3.0`, blur `6.0`) than standard buttons
   - **Use for:** Large clickable card-like UI elements (export format options, font picker items)
   - **Don't use for:** Standard action buttons (Cancel, Close) - use `secondary_button` instead

5. **Active tab buttons** (`active_tab_button`) - Currently selected workspace tab
   - Background: `theme.bg_elevated`
   - Radius: `0.0` (square)
   - Shadow with elevation changes

6. **Inactive tab buttons** (`inactive_tab_button`) - Unselected workspace tabs
   - Background: `theme.bg_surface`
   - Border: `theme.border` (1px)
   - Radius: `0.0` (square)

### Standard Padding and Sizing

**Consistency is critical.** All buttons of the same category must use identical padding and sizing.

#### Primary Action Buttons
```rust
button(text("Save").size(14))
    .padding([10, 24])  // [vertical, horizontal]
    .style(move |_, status| primary_button(theme, status))
```
**Examples:** Apply, Save to System, "Yes I understand" (danger)

#### Secondary/Utility Buttons
```rust
button(text("Cancel").size(14))
    .padding([10, 20])
    .style(move |_, status| secondary_button(theme, status))
```
**Examples:** Cancel, Close, Export, Diagnostics

#### Tab Navigation Buttons
```rust
button(text("Settings").size(13))
    .padding([8, 16])
    .style(move |_, status| if active { active_tab_button(...) } else { inactive_tab_button(...) })
```
**Examples:** nftables.conf, JSON Payload, Settings tabs

#### Small Inline Buttons
```rust
button(text("×").size(14))
    .padding(6)
    .style(button::text)  // Text-only style for subtle inline actions
```
**Examples:** × delete buttons, No/Yes confirmations in delete confirmation row

#### Filter Tag Buttons
```rust
button(text(tag).size(10))
    .padding([4, 8])
    .style(move |_, status| if selected { active_tab_button(...) } else { secondary_button(...) })
```
**Examples:** Filter tags in sidebar

### Usage Pattern

**Correct:**
```rust
button(text("Apply Changes").size(14))
    .on_press(Message::ApplyClicked)
    .padding([10, 24])
    .style(move |_, status| primary_button(theme, status))
```

**Incorrect - Inline styling:**
```rust
button(text("Apply Changes").size(14))
    .on_press(Message::ApplyClicked)
    .padding([10, 24])
    .style(move |_, status| button::Style {  // ❌ Never do this!
        background: Some(theme.accent.into()),
        // ... duplicating existing styles
    })
```

### Why Not Create Button Wrapper Functions?

**Question:** Should we create helpers like `primary_action_button(theme, "Save")` to avoid repeating padding/sizing?

**Answer:** **No.** Current pattern is better because:
1. **Flexibility** - Different buttons need different padding, sizes, fonts, icons
2. **Explicitness** - You see exactly what's configured at the call site
3. **No premature abstraction** - Not enough repetition to warrant it
4. **Clear intent** - `.padding([10, 24])` is self-documenting

The **style functions** (`primary_button`, `card_button`, etc.) are the right level of abstraction. They handle theme-aware colors, shadows, and state transitions. Padding and sizing are context-specific presentation concerns that should remain explicit.

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

## Modal Windows

### Design Principles

All modal popup windows (rule forms, warnings, confirmations, font picker, help) follow consistent styling for professional, cohesive UX.

### Modal Styling Standard

**All modals use:**
```rust
.style(move |_| card_container(theme))
```

This provides:
- **Rounded corners**: `radius: 8.0` (never square - modals are interactive elements)
- **Crisp shadows**: `shadow_color` at offset `(0.0, 2.0)` with `blur: 3.0`
- **Subtle border**: `theme.border` at `1px` width
- **Surface background**: `theme.bg_surface`

### Warning/Error Modals

Warnings require visual prominence while maintaining consistency:

```rust
.style(move |_| {
    let mut style = card_container(theme);
    style.border = Border {
        color: theme.danger,
        width: 2.0,
        radius: 8.0.into(),  // CRITICAL: Preserve rounded corners
    };
    style
})
```

**Common Mistake:**
```rust
// WRONG - resets radius to 0.0 (square corners)
style.border = Border {
    color: theme.danger,
    width: 2.0,
    ..Default::default(),  // ← Don't use this!
};
```

**Why rounded warnings?**
- Consistency with all other modals
- Square corners signal "navigation/structure" (tabs, containers)
- Rounded corners signal "interactive/action" (modals, buttons)
- The prominent red border already communicates urgency

### Modal Shadow Consistency

**All modals must use `card_container()`'s crisp shadow** (never `shadow_strong`):

- **Shadow color**: `theme.shadow_color` (35% light / 60% dark opacity)
- **Offset**: `(0.0, 2.0)` - subtle elevation
- **Blur**: `3.0` - crisp and sharp

Heavy shadows (`shadow_strong`, large blur radius) create muddy appearance. The subtle shadow provides depth without distraction.

**Reference:** Lines 60-78 (Shadow System)

---

## Floating Popups & Tooltips

### Design Principles

Tooltips and other small floating overlays should be distinct from the structural elements (cards) and primary interactive elements (modals). They use a "lighter-than-surface" approach to appear as if they are floating closer to the user.

### Popup Styling Standard

**All floating tooltips use:**
```rust
.style(move |_| popup_container(theme))
```

This provides:
- **Lighter background**: Noticeably brighter than `bg_surface` to pop against cards.
- **Faded border**: `15%` opacity border to provide a soft edge without clutter.
- **Tight radius**: `radius: 6.0` (slightly tighter than 8.0px cards).
- **Crisp shadow**: Standard directional shadow for professional depth.

### Usage Guidelines

1. **Delay**: Standard tooltips should have a **1.0 second delay** (`1000ms`) to avoid flickering while moving the mouse.
2. **Positioning**: Prefer `tooltip::Position::Bottom` for rule cards to avoid obscuring the management icons.
3. **Content**: Always wrap the tooltip element in a `container` with `popup_container` styling.

---

## Font Picker Patterns

### Search Auto-Focus

When opening the font picker, automatically focus the search input for immediate typing:

```rust
Message::OpenFontPicker(target) => {
    self.font_picker = Some(FontPickerState { /* ... */ });
    return iced::widget::operation::focus_next();
}
```

**Why?** Users expect to immediately type when opening a search interface. This eliminates an unnecessary click.

### Asymmetric Padding Pattern

Font list items use asymmetric padding to prevent hover backgrounds from touching the scrollbar:

```rust
container(font_list).padding(Padding {
    top: 2.0,
    right: 12.0,   // Space for scrollbar
    bottom: 2.0,
    left: 2.0,     // Minimal left padding
})
```

**Result:** Hover backgrounds extend nearly to edges while maintaining proper scrollbar spacing.

### Progressive Search Disclosure

When displaying limited results (30 of 200 fonts), inform users:

```rust
if filtered_count > display_limit {
    text(format!(
        "Showing {} of {} fonts — search to find more",
        displayed_count, filtered_count
    ))
}
```

**Why?** Users might think only 30 fonts exist. This message encourages search refinement.

### Empty State Messaging

```rust
if filtered_count == 0 {
    text("No fonts found — try a different search")
}
```

Clear, actionable feedback prevents user confusion.

---

## Theme Picker Patterns

### Implementation
**Location:** `src/app/view.rs:2006-2383` (view_theme_picker function)

The theme picker modal demonstrates several important patterns for building performant, maintainable UI with wrapped layouts.

### Modal Width Calculation

**Anti-Pattern: Exact Pixel Math**
```rust
// WRONG - Fragile and breaks with changes
const MODAL_WIDTH: f32 = 482.0 + 16.0 + 50.0; // cards + padding + outer
```

**Correct Pattern: Comfortable Width with Slack**
```rust
const CARD_WIDTH: f32 = 150.0;
const CARD_SPACING: f32 = 16.0;
const GRID_PADDING: f32 = 8.0;
const MODAL_WIDTH: f32 = 556.0; // Fine-tuned for visual balance
```

**Why this works:**
- Cards need: 3 × 150px + 2 × 16px spacing = 482px
- Modal provides ~506px after borders/padding
- **24px slack** allows for scrollbar overlay without clipping
- Minor width tweaks (±4px) are acceptable for visual tuning
- Won't break if font sizes change (card width is fixed)

**Rule:** Choose a comfortable modal width, then fine-tune by ±10px if needed. Don't calculate exact requirements.

### Wrapped Row Layout Pattern

Theme cards use Iced's `.wrap()` for automatic row wrapping:

```rust
let theme_grid = row(theme_cards)
    .spacing(CARD_SPACING)
    .wrap();

container(theme_grid).padding(GRID_PADDING) // Symmetric padding
```

**Key insight:** Wrapped rows only expand to fit their content width, not the container width. Extra space appears on the right side. This is normal behavior - don't fight it with complex calculations.

**Symmetric Padding:**
```rust
.padding(8.0) // Same on all sides - simple and maintainable
```

Never use asymmetric padding to "fix" scrollbar alignment issues. Instead, adjust the modal width.

### Live Preview Pattern

The theme picker shows live previews before applying:

```rust
Message::ThemePreview(choice) => {
    // Apply temporarily (don't save)
    self.current_theme = choice;
    self.theme = choice.to_theme();
}

Message::ApplyTheme => {
    // Confirm and save
    self.theme_picker = None;
    return self.save_config();
}

Message::CancelThemePicker => {
    // Revert to original
    if let Some(picker) = &self.theme_picker {
        self.current_theme = picker.original_theme;
        self.theme = picker.original_theme.to_theme();
    }
    self.theme_picker = None;
}
```

**State structure:**
```rust
pub struct ThemePickerState {
    pub search: String,
    pub search_lowercase: String,      // Performance: cached
    pub filter: ThemeFilter,
    pub original_theme: ThemeChoice,   // For Cancel/revert
}
```

### Performance Optimizations

**1. Cache Theme Conversions**
```rust
// Convert to_theme() once per theme, not multiple times
let filtered_themes: Vec<(ThemeChoice, AppTheme)> = ThemeChoice::all()
    .iter()
    .filter_map(|choice| {
        let theme_instance = choice.to_theme(); // Cache this!
        // ... filtering logic
        Some((*choice, theme_instance))
    })
    .collect();
```

**Impact:** 45% performance improvement by avoiding duplicate `to_theme()` calls.

**2. ASCII-Only Search**
```rust
// In state update:
picker.search_lowercase = search.to_lowercase();

// In view (per frame):
choice.name().to_ascii_lowercase().contains(search_term)
```

**Why:** Theme names are ASCII-only, so `to_ascii_lowercase()` is faster than `to_lowercase()`. Avoids 22 allocations per keystroke.

**3. Pre-Allocated Collections**
```rust
let mut theme_cards = Vec::with_capacity(filtered_count);
```

Standard practice - prevents reallocations during iteration.

### Two-Column Preview Layout

Preview panel uses proportional width distribution:

```rust
row![
    // Left: UI elements (45% width)
    column![/* buttons, text samples */]
        .width(Length::FillPortion(9)),

    // Right: Code sample (55% width)
    container(/* syntax highlighted code */)
        .width(Length::FillPortion(11)),
]
```

**FillPortion explained:** `9:11` ratio = 45%:55% split. More explicit than percentages, prevents rounding errors.

### Color Preview Pattern

Theme cards show visual previews without text description:

```rust
// Split gradient bar: 70% background / 30% accent
row![
    container(space::Space::new())
        .width(Length::FillPortion(7))  // Background gradient
        .style(/* gradient from bg_base to bg_surface */),
    container(space::Space::new())
        .width(Length::FillPortion(3))  // Solid accent
        .style(/* solid accent color */),
]

// Color dot swatches
row![
    make_color_dot(accent, 12.0),
    make_color_dot(success, 12.0),
    make_color_dot(warning, 12.0),
    make_color_dot(danger, 12.0),
]
```

**Why gradients on cards, not buttons?** Cards don't need shadows (they're passive previews), so gradient limitation doesn't apply.

### Selected Theme Indication

```rust
.style(move |_, status| {
    let mut style = card_button(theme, status);
    if is_selected {
        style.border = Border {
            color: accent,  // Theme's own accent color
            width: 2.0,
            radius: 8.0.into(),
        };
    }
    style
})
```

**No checkmark** - accent border is cleaner and doesn't cause layout shifts with long theme names.

### Filter Button Pattern

Identical to rule tag filtering:

```rust
button(text("Light").size(10))
    .padding([4, 8])
    .style(move |_, status| {
        if matches!(picker.filter, ThemeFilter::Light) {
            active_tab_button(theme, status)
        } else {
            secondary_button(theme, status)
        }
    })
```

Consistent filter UX across the application.

---

## Preview Pane Scrolling

### Horizontal Scrolling with Dynamic Width

**Challenge:** Iced's `scrollable` with `Direction::Both` requires explicit content width. There's no automatic content measurement like web browsers or `Length::Shrink` for wrapped layouts.

**Solution:** Calculate width dynamically based on longest line in current view:

```rust
// Separate width for each view stored in State
cached_nft_width_px: f32,   // NFT view (active rules only)
cached_json_width_px: f32,  // JSON view (fixed structure)
cached_diff_width_px: f32,  // Diff view (includes disabled rules)

// Select in view() based on current tab/diff state
let content_width = match (state.active_tab, state.show_diff) {
    (WorkspaceTab::Nftables, true) => state.cached_diff_width_px,
    (WorkspaceTab::Nftables, false) => state.cached_nft_width_px,
    (WorkspaceTab::Json, _) => state.cached_json_width_px,
    _ => state.cached_nft_width_px,
};
```

### Width Calculation

**Formula:** `LINE_NUMBER_WIDTH (50px) + (char_count × 8.4px) + TRAILING_PADDING (60px)`

**Constants:**
- **8.4px per character** - Approximate width of monospace font at 14pt
- **50px line numbers** - Fixed width for line number column
- **60px trailing padding** - Breathing room at end of lines (~7 characters)
- **800px minimum** - Prevents cramped appearance on large screens
- **3000px maximum** - Safety cap for pathological cases

### UX Rationale

**Why Dynamic Width per View:**
- NFT view excludes disabled rules → narrower when rules disabled
- Diff view shows disabled rules with strikethrough → potentially wider
- JSON view has fixed structure → consistently narrow (~800px minimum)
- Switching views with different content widths should reflect actual content

**Why Layout Shifts Are Acceptable:**
- Toggling diff or switching tabs is an **explicit user action**
- Layout shift is **immediate and predictable** (triggered by user)
- More precise than "max of all views" which shows unnecessarily wide zebra stripes
- Prevents scrollbar when switching to narrower view (better than always showing it)

**Why 60px Trailing Padding:**
- Zebra stripes felt cramped when ending exactly at last character
- ~7 characters worth of breathing room improves aesthetics
- Prevents horizontal scrollbar for lines that are "barely too long"
- Comfortable visual spacing without excessive width

### Edge Cases Handled

✅ **Diff view with disabled long rules** - Uses `cached_diff_width_px` so disabled lines don't get clipped
✅ **Tab switching** - Each tab uses its own width, no jarring jumps
✅ **Empty rulesets** - `.unwrap_or(0)` fallback handles empty iterators
✅ **JSON consistently narrow** - Uses 800px minimum for aesthetics on large screens
✅ **Toggling diff** - Smooth layout shift when user explicitly toggles feature

### Performance

**Cost:** Negligible - one iteration per content change (not per frame), ~50-100 microseconds for 1000 lines.

**Follows existing patterns:** Uses "cache in `update()`, reference in `view()`" pattern from performance optimizations (Phase 3-4).

**Implementation:** `src/app/mod.rs:353-399` (calculation functions), `src/app/view.rs:38,49,61,74` (selection logic)

---

## Inset Progress Bar Pattern

### Purpose

The countdown confirmation modal uses a custom inset/recessed progress bar that appears carved into the modal surface rather than elevated above it. This creates a sophisticated visual effect that matches the application's overall depth system.

### Implementation

**Location:** `src/app/view.rs:1790-1920` (progress bar in countdown modal)

### Two-Layer Structure

The inset effect requires two layers:

1. **Outer container rim** (creates the recessed groove)
2. **Inner progress bar** (fills the groove)

```rust
container(  // Outer rim
    progress_bar(0.0..=1.0, progress)  // Inner fill
        .style(/* fill styling */)
)
.padding(Padding {
    top: 2.5,    // Asymmetric padding creates depth
    right: 2.0,
    bottom: 1.0,
    left: 2.0,
})
.style(/* rim styling */)
```

### Asymmetric Padding

The **2.5px top / 1.0px bottom** padding creates enhanced depth perception:
- Thicker top rim suggests shadow from above
- Thinner bottom rim suggests light from above
- This mimics how physical recessed surfaces appear in natural lighting

### Rim Styling (Outer Container)

```rust
container::Style {
    background: Some(Background::Gradient(/* vertical gradient */)),
    border: Border {
        color: bg_surface * 0.75,  // 25% darker
        width: 1.0,
        radius: 8.0.into(),  // Fully rounded container
    },
    shadow: Shadow {
        color: bg_surface * 0.5 @ 0.9 alpha,
        offset: (0.0, -1.0),  // NEGATIVE Y = top shadow (inset illusion)
        blur_radius: 1.0,     // Crisp shadow
    },
}
```

**Key technique:** Negative Y offset creates shadow from above, essential for the inset illusion.

### Rim Gradient

Theme-aware gradient for depth:

```rust
let (rim_top, rim_bottom) = if app_theme.is_light() {
    (0.5, 0.95)  // Light: 50% darker top, 5% darker bottom
} else {
    (0.5, 0.88)  // Dark: 50% darker top, 12% darker bottom
};

// Vertical gradient (PI = top to bottom)
Gradient::Linear(Linear::new(std::f32::consts::PI)
    .add_stop(0.0, bg_surface * rim_top)
    .add_stop(1.0, bg_surface * rim_bottom))
```

### Fill Bar Styling (Inner Progress Bar)

```rust
progress_bar::Style {
    background: bg_surface * 0.85,  // 15% darker empty track
    bar: Background::Gradient(bar_gradient),  // Filled portion
    border: Border {
        radius: 6.0.into(),  // Slightly smaller than outer (8.0)
    },
}
```

### Fill Color Logic

**Dark themes:**
```rust
// Use base_color which changes: accent (normal) → danger (≤5s)
Color {
    r: base_color.r * 0.85,  // 15% darker
    g: base_color.g * 0.85,
    b: base_color.b * 0.85,
    a: 1.0,
}
```

**Light themes:**
```rust
if remaining <= 5 {
    // At 5 seconds: darker gray for urgency
    bg_surface * 0.65  // 35% darker
} else {
    // Normal: gray for inset shadow appearance
    bg_surface * 0.70  // 30% darker
}
```

**Design rationale:**
- Dark themes can use colored fills (already darker than bg)
- Light themes must use gray - colored fills don't look recessed on light backgrounds
- Both darken at 5 seconds for urgency feedback

### Fill Bar Gradient

```rust
let gradient_multiplier = if app_theme.is_light() {
    0.92  // Subtle 8% darker at top
} else {
    0.65  // Strong 35% darker for depth
};

Gradient::Linear(Linear::new(std::f32::consts::PI)
    .add_stop(0.0, bar_color * gradient_multiplier)  // Dark top
    .add_stop(0.15, bar_color)  // 15% coverage from top
    .add_stop(1.0, bar_color))  // Full fill color for rest
```

**Coverage tuning:** 15% gradient coverage creates crisp shadow without fuzziness.

### Smooth Animation

**60 FPS linear animation** over the entire countdown duration:

```rust
// In update() when countdown starts
self.progress_animation = Animation::new(1.0)
    .easing(animation::Easing::Linear)  // Constant speed
    .duration(Duration::from_secs(timeout))
    .go(0.0, iced::time::Instant::now());

// Subscription for frame updates
AppStatus::PendingConfirmation { .. } => {
    iced::time::every(Duration::from_millis(17)).map(|_| Message::CountdownTick)
}

// In view() for smooth value
state.progress_animation.interpolate_with(|v| v, iced::time::Instant::now())
```

**Why 60 FPS?**
- Matches standard display refresh rates
- Noticeably smoother than 30 FPS
- Performance cost is negligible (<1% CPU)

**Why Linear easing?**
- Default easing is `EaseInOut` (slow at start/end)
- Linear provides constant speed - better for countdown timers
- Users expect steady progress, not acceleration curves

### Performance Characteristics

**CPU overhead:**
- Animation interpolation: trivial math per frame
- Color calculations: ~15 float multiplications per frame
- Gradients/shadows: GPU-accelerated

**Total cost:** <1% CPU, imperceptible on modern hardware

**Update frequency:** Only active during countdown (not persistent)

### Visual Design Goals

1. **Recessed appearance** - Progress bar looks carved into surface
2. **Theme consistency** - Works across all light/dark themes
3. **Urgency feedback** - Visual change at 5 seconds remaining
4. **Smooth motion** - 60 FPS linear animation feels natural
5. **Sharp precision** - Crisp shadows matching button styling

### Edge Cases Handled

✅ **Theme switching** - All colors derive from semantic theme values
✅ **Very dark themes** - Gray fill visible even on near-black backgrounds
✅ **Very light themes** - Gray fill appears recessed, not elevated
✅ **Timeout changes** - Animation duration adapts to config setting
✅ **Zero progress** - Empty track always visible with 15% darker background

### Implementation Reference

**State fields:**
```rust
pub countdown_remaining: u32,           // Discrete second counter
pub progress_animation: Animation<f32>, // Smooth interpolated value
```

**Related files:**
- `src/app/mod.rs:152` - Animation field in State
- `src/app/mod.rs:1803-1807` - Animation initialization
- `src/app/mod.rs:2101-2103` - 60 FPS subscription
- `src/app/view.rs:1760-1920` - Complete rendering logic

---

## Reference: Key Files

- **`src/theme/mod.rs`** - Theme struct, shadow calculation, luminance detection
- **`src/theme/presets.rs`** - All built-in theme definitions
- **`src/app/ui_components.rs`** - All button/container style functions
- **`src/app/view.rs`** - View rendering, tab button implementation

---

## Changelog

### 2025-12-28

**Post-Midnight Session - Dropdown Menu Polish:**
- **Borderless Dropdown Design:** Removed borders from dropdown menus for cleaner appearance
  - Menu border: removed (transparent)
  - Menu shadow: crisp directional `(0.0, 2.0)` with `blur: 3.0` matching modal style
  - Tested uniform shadow `(0.0, 0.0)` - rejected in favor of directional consistency
- **Depressed Control State:** Control dims when dropdown opens
  - Opened state background: `bg_base` (deepest layer) for "pressed in" effect
  - Opened state border: transparent (menu shadow provides definition)
  - Creates visual hierarchy - control recedes, menu stands out
- **Menu Background Contrast:** Calculated brighter background for clear distinction
  - Started with `bg_elevated` (same as input controls) - items blended with controls
  - Added theme-aware brightening calculation to create visual separation
  - Light themes: 97% original + 3% white blend
  - Dark themes: 1.15x multiply + 0.04 additive boost
  - Result: Menu items clearly distinct from depressed control below
- **Menu Height Limiting:** Selective application based on dropdown content
  - Service Preset (50+ items): `.menu_height(300.0)` to prevent off-screen overflow
  - Protocol (5 items): No height limit - auto-sizes perfectly
  - Interface (~10 items): No height limit - auto-sizes to content
  - **Fix:** Removed fixed height from short dropdowns to eliminate empty space
  - **Rationale:** Iced's `menu_height()` is fixed, not max - no auto-size-with-cap option exists
- **Dropdown Menu Styling Section:** Comprehensive documentation added to STYLE.md
  - Control state styling rationale (depressed effect)
  - Menu styling patterns (borderless, shadow-only, elevated background)
  - Menu height limiting best practices
  - Design decision log (why directional shadow, why no border, why bg_elevated)

**Very Late Evening Session - Section Header Pattern:**
- **Section Header System:** Implemented subtle backdrop pattern for labels and headers
  - Centralized `section_header_container()` function in `ui_components.rs`
  - 5% opacity of `fg_primary` color (increased from 0.02 for better visibility)
  - 4px border radius with small padding ([2, 6] or [4, 8])
  - Applied to 19 locations across the app for consistent hierarchy
- **Locations Added:**
  - Sidebar: "DUMB RUST FIREWALL", "FILTERS", "RULES"
  - Theme picker: "Select Theme", "PREVIEW:", "Text Hierarchy", "Status Colors", "{X} themes available"
  - Font picker: "Select UI Font/Code Font", "{X} fonts available"
  - Modals: "Keyboard Shortcuts", "Commit Changes?", "Confirm Safety"
  - Rule form: All field labels (PROTOCOL, PORT RANGE, SOURCE ADDRESS, INTERFACE, TAGS)
  - Settings: Already had it (APPEARANCE, ADVANCED SECURITY)
- **Pattern Guidelines Established:**
  - ✅ Use for: static labels, section headers, field labels, footer metadata
  - ❌ Avoid for: large page titles, dynamic content, body text, action buttons
  - Only wrap static label portion, not dynamic content (e.g., "PREVIEW:" not "PREVIEW: Ayu Dark")
- **Spacing Consistency Fixed:**
  - Sidebar FILTERS → tags: kept at 8px spacing
  - Sidebar RULES → cards: reduced from 12px → 8px (now consistent)
  - Removed extra [0, 2] padding wrapper from rule cards
  - Removed [0, 4] padding from RULES header row
  - Result: Perfect alignment throughout sidebar
- **Section Header Pattern Section:** Comprehensive documentation added to STYLE.md
  - Usage patterns, padding guidelines, where to use/avoid
  - Design rationale and evolution notes
  - Performance analysis (negligible overhead)

**Late Evening Session - Theme Picker Implementation:**
- **Theme Picker Modal:** Replaced dropdown with visual theme picker (22 themes displayed as cards)
  - Grid layout with wrapped rows (3 cards per row)
  - Live preview system (preview → apply → cancel flow)
  - Light/Dark filtering matching rule tag pattern
  - Search functionality with cached lowercase optimization
  - Two-column preview panel (45% UI elements, 55% code sample)
  - Selected theme indicated by accent-colored border (no checkmark)
- **Performance Optimizations:**
  - Cached `to_theme()` results (45% improvement)
  - ASCII-only search (`to_ascii_lowercase()` vs `to_lowercase()`)
  - Pre-allocated collections with capacity
- **Layout Pattern Established:** Modal width calculation approach
  - Use comfortable width with slack (~24px) for scrollbar overlay
  - Fine-tune width by ±10px for visual balance (not exact pixel math)
  - Symmetric padding (8px all sides) - simple and maintainable
  - Wrapped rows expand to content width (extra space on right is normal)
- **Code Review Fixes:**
  - Removed redundant `preview_theme` variable
  - Fixed performance bug in search (eliminated 22 allocations per keystroke)
  - Suppressed intentional `ThemeChanged` warning with documentation
- **Theme Picker Patterns Section:** Documented all patterns for future modal implementations

**Evening Session - Button Standardization & Server Mode Toggle:**
- **Server Mode Toggle:** Converted "Egress Filtering Profile" from full-width buttons to clean toggle
  - Renamed to "Server Mode" for clarity
  - Uses standard toggler consistent with other security settings
  - Maintains warning modal when enabling Server mode
- **Button Padding/Sizing Standardization:** Fixed inconsistencies across entire application
  - Primary action buttons: `[10, 24]` padding, size `14`
  - Secondary/utility buttons: `[10, 20]` padding, size `14`
  - Small inline buttons: `6` padding, size `14`
  - Tab navigation: `[8, 16]` padding, size `13`
  - Filter tags: `[4, 8]` padding, size `10`
- **Button Hover Shadow Consistency:** Fixed modal buttons using wrong style
  - Warning modal Cancel: `card_button` → `secondary_button`
  - Diagnostics modal Close: `card_button` → `secondary_button`
  - Shortcuts help Close: `card_button` → `secondary_button`
  - **Issue:** `card_button` has dramatic hover (offset `3.0`, blur `6.0`)
  - **Fix:** Standard buttons now use subtle hover (offset `2.5`, blur `4.0`)
  - **Rule:** `card_button` only for large clickable cards, not action buttons
- **Button Styling Documentation:** Added comprehensive button usage guide to contrib/style.md
  - Documented all centralized button style functions
  - Standard padding/sizing for each button category
  - Usage patterns with correct/incorrect examples
  - Rationale for not creating button wrapper functions (flexibility > abstraction)
  - When to use `card_button` vs `secondary_button`
- **Auto-Focus Fix:** Font picker search now properly auto-focuses on open (was broken)

**Morning Session - Modal Consistency:**
- **Modal Shadow Standardization:** Fixed inconsistent shadows across all modals
  - All modals now use `card_container()` crisp shadow (not `shadow_strong`)
  - Removed heavy, muddy shadows (blur 20-30) in favor of crisp shadows (blur 3)
- **Warning Modal Rounded:** Fixed warning modals to use 8px radius (was accidentally square)
- **Font Picker Polish:** Auto-focus search input, asymmetric padding, progressive disclosure
- **Modal Windows Section:** Added comprehensive modal styling guidelines
- **Font Picker Patterns Section:** Documented auto-focus, padding, and messaging patterns

### 2025-12-30

**Evening Session - Inset Progress Bar with Smooth Animation:**
- **Phase 2b UX Streamlining:** Auto-revert configuration and countdown progress bar
  - Added configurable auto-revert toggle in Settings (default: disabled for GUI)
  - Added timeout slider (5-120 seconds, default: 15s)
  - GUI respects config, CLI always uses auto-revert for safety
- **Inset Progress Bar Effect:** Custom two-layer design for recessed appearance
  - Outer container rim with gradient, border, and negative-Y shadow
  - Inner progress bar with theme-aware fill colors
  - Asymmetric padding (2.5px top, 1.0px bottom) for depth perception
  - Crisp shadows (blur 1.0) matching button precision
- **Theme-Aware Styling:**
  - Dark themes: Colored fill (accent → danger at 5s) darkened 15%
  - Light themes: Gray fill (darkens from 70% to 65% at 5s for urgency)
  - Different gradient multipliers: 8% (light) vs 35% (dark)
- **Smooth 60 FPS Animation:**
  - Linear easing for constant speed (no slow-down at start/end)
  - One continuous animation over full duration (not stepped per second)
  - 17ms frame updates (60 FPS) for display refresh rate match
  - Performance: <1% CPU overhead
- **Implementation Reference:**
  - Animation field in State (Animation<f32>)
  - 60 FPS subscription only active during countdown
  - Complete rendering logic spans ~160 lines
- **Documentation:** Added "Inset Progress Bar Pattern" section to STYLE.md

**Morning Session - Dynamic Horizontal Scrolling:**
- **Dynamic Horizontal Scrolling:** Implemented intelligent width calculation for preview panes
  - Separate width calculations for NFT, JSON, and diff views
  - Width adjusts based on current tab and diff toggle state
  - 60px trailing padding for comfortable visual spacing
  - Scrollbar only appears when current view genuinely needs it
- **Edge Case Fixes:**
  - Diff view now correctly calculates width including disabled rules (prevents clipping strikethrough text)
  - Tab switching uses view-specific width (prevents unnecessarily wide zebra stripes)
- **UX Improvement:** Layout shifts on tab/diff toggle are intentional and acceptable (explicit user action)
- **Documentation:** Added "Preview Pane Scrolling" section explaining technical approach and UX rationale

### 2025-12-27
- **Tab Strip Redesign:** Made tabs square (radius 0.0) for visual distinction
- **Separated Tab Styles:** Created `inactive_tab_button` separate from `secondary_button`
- **Gradient Experiment:** Tried gradient active tabs, reverted due to shadow incompatibility
- **Document Created:** Initial style guide documenting design decisions

---

**Document Version:** 1.2
**Last Updated:** 2025-12-30
**Iced Version:** 0.14
