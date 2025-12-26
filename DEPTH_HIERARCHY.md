# UI Depth Hierarchy & Shadow System

This document defines the consistent depth hierarchy used throughout the DRFW application for shadows and visual elevation.

## Shadow Levels

### Level 0: Base (No Shadow)
- **Usage**: Background elements, disabled states
- **Shadow**: None (`Color::TRANSPARENT`)
- **Elements**: Disabled buttons

### Level 1: Resting State (2px/4px)
- **Usage**: Cards, buttons, inputs at rest
- **Shadow**: `offset: (0, 2px)`, `blur: 4px`
- **Elements**:
  - Rule cards (default state)
  - All buttons (default state)
  - Card containers
  - Input fields

### Level 2: Hover State (3px/6px)
- **Usage**: Interactive elements on hover
- **Shadow**: `offset: (0, 3px)`, `blur: 6px`
- **Elements**:
  - Buttons on hover
  - Rule cards during drag drop target hover
  - Interactive cards on hover

### Level 3: Elevated (4px/8px)
- **Usage**: Floating elements, dragged items
- **Shadow**: `offset: (0, 4px)`, `blur: 8px`
- **Elements**:
  - Rule cards being dragged
  - Modal dialogs (some use even higher: 10px/20px)
  - Tooltips

### Pressed State (1px/2px)
- **Usage**: Buttons being clicked
- **Shadow**: `offset: (0, 1px)`, `blur: 2px`
- **Effect**: Creates satisfying "pressed down" effect
- **Elements**: All buttons when clicked

## Button States

### Primary Button
- **Resting**: Blue accent, 2px/4px shadow
- **Hover**: Lighter blue, 3px/6px shadow (elevated)
- **Pressed**: Original blue, 1px/2px shadow (depressed)
- **Disabled**: 50% opacity, no shadow, muted text

### Secondary Button
- **Resting**: Surface color, border, 2px/4px shadow
- **Hover**: Hover background, 3px/6px shadow (elevated)
- **Pressed**: Original surface, 1px/2px shadow (depressed)
- **Disabled**: 50% opacity background, 30% opacity border, no shadow, muted text

### Danger Button
- **Resting**: Red, 2px/4px shadow
- **Hover**: Brighter red, 3px/6px shadow (elevated)
- **Pressed**: Original red, 1px/2px shadow (depressed)
- **Disabled**: 50% opacity, no shadow, muted text

### Card Buttons
- **Resting**: Same as card_container (2px/4px shadow)
- **Hover**: 3px/6px shadow (elevated)
- **Pressed**: 1px/2px shadow (depressed)

### Tab Buttons (Active)
- **Resting**: Elevated background, 2px/4px shadow
- **Hover**: Hover background, 3px/6px shadow (elevated)
- **Pressed**: Original background, 1px/2px shadow (depressed)

## Cards & Containers

### Rule Cards
- **Default**: 2px/4px shadow (Level 1)
- **Being Dragged**: 4px/8px shadow (Level 3) with accent border
- **Drop Target Hover**: 3px/6px shadow (Level 2) with success border
- **Editing**: Active background with accent border

### Modal Dialogs
- **Standard**: 4px/8px shadow (Level 3)
- **Warning/Error Modals**: 10px/20px shadow (extra elevated for importance)

## Tooltips
- **Shadow**: 2px/4px (Level 1)
- **Background**: Dark with border
- **Purpose**: Subtle but readable

## Implementation Guidelines

1. **Consistency**: All interactive elements use the same shadow progression:
   - Rest → Hover → Pressed
   - 2px/4px → 3px/6px → 1px/2px

2. **Disabled State**: Always has no shadow and reduced opacity to clearly indicate non-interactivity

3. **Visual Feedback**: The hover lift (2px→3px) and press depress (2px→1px) creates satisfying physical feedback

4. **Performance**: Shadows are only used where they enhance UX (buttons, cards, modals), not everywhere

5. **Z-Index Hierarchy**:
   - Level 0 (disabled): Visually receded
   - Level 1 (resting): Normal content layer
   - Level 2 (hover): Slightly elevated for interaction
   - Level 3 (floating): Clearly above content (modals, drag)

## Rationale

This shadow system is inspired by Aseprite and Material Design principles, providing:
- **Clear affordances**: Users can tell what's clickable
- **Satisfying feedback**: Physical button press feel
- **Visual hierarchy**: Important elements float above others
- **Accessibility**: Disabled states are visually distinct
- **Consistency**: Same patterns across all UI elements
