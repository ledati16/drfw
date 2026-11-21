//! Keyboard focus: text input ids, autofocus, the Tab cycle and the "is a
//! text input focused?" query the shortcuts use.
//!
//! In iced 0.14 only text inputs take keyboard focus (buttons, checkboxes,
//! pick lists and combo boxes don't). Tab therefore moves between the text
//! inputs of the top-most layer; inputs of the layers beneath, hidden behind
//! a modal, are skipped and lose focus, so typing never lands in a field the
//! user can't see.

use iced::advanced::widget::operation::focusable::{self, Focusable};
use iced::advanced::widget::operation::{Operation, Outcome};
use iced::advanced::widget::{Id, operate};
use iced::{Rectangle, Task};

/// Sidebar rule search
pub const RULE_SEARCH: &str = "rule-search";
/// Settings: log prefix of dropped packets
pub const LOG_PREFIX: &str = "log-prefix";
/// Rule form: description (the first input, focused when the form opens)
pub const RULE_FORM_LABEL: &str = "rule-form-label";
/// Rule form: rate limit count
pub const RULE_FORM_RATE_COUNT: &str = "rule-form-rate-count";
/// Rule form: rate limit burst
pub const RULE_FORM_RATE_BURST: &str = "rule-form-rate-burst";
/// Rule form: connection limit
pub const RULE_FORM_CONNECTION_LIMIT: &str = "rule-form-connection-limit";
/// Port / address / tag helper input
pub const HELPER_INPUT: &str = "helper-input";
/// Profile manager: name of a new profile
pub const PROFILE_NEW_NAME: &str = "profile-new-name";
/// Profile manager: new name of the profile being renamed
pub const PROFILE_RENAME: &str = "profile-rename";
/// Diagnostics: event search
pub const DIAGNOSTICS_SEARCH: &str = "diagnostics-search";
/// Font picker search
pub const FONT_SEARCH: &str = "font-search-input";
/// Theme picker search
pub const THEME_SEARCH: &str = "theme-search";

/// Focuses the text input with `id` (and unfocuses every other one).
pub fn focus_input<T>(id: &'static str) -> Task<T> {
    iced::widget::operation::focus(Id::new(id))
}

/// Resolves to whether any text input has keyboard focus.
pub fn any_input_focused() -> Task<bool> {
    operate(focusable::count()).map(|count| count.focused.is_some())
}

/// Moves focus to the next (`forward`) or previous of the inputs `ids` that
/// are on screen, in layout order and wrapping around. With none of them
/// focused, the first (last) one is focused. Any other focused input loses
/// focus. Does nothing if none of `ids` is on screen.
pub fn cycle<T>(ids: &'static [&'static str], forward: bool) -> Task<T>
where
    T: Send + 'static,
{
    operate(Scan {
        ids,
        forward,
        seen: 0,
        focused: None,
    })
    .discard()
}

fn is_listed(ids: &[&'static str], id: Option<&Id>) -> bool {
    id.is_some_and(|id| ids.iter().any(|listed| *id == Id::new(listed)))
}

/// First pass of [`cycle`]: counts the listed inputs and finds the focused one.
struct Scan {
    ids: &'static [&'static str],
    forward: bool,
    seen: usize,
    focused: Option<usize>,
}

impl Operation for Scan {
    fn focusable(&mut self, id: Option<&Id>, _bounds: Rectangle, state: &mut dyn Focusable) {
        if is_listed(self.ids, id) {
            if state.is_focused() {
                self.focused = Some(self.seen);
            }
            self.seen += 1;
        }
    }

    fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation)) {
        operate(self);
    }

    fn finish(&self) -> Outcome<()> {
        let Some(target) = cycle_target(self.seen, self.focused, self.forward) else {
            return Outcome::None;
        };
        Outcome::Chain(Box::new(Apply {
            ids: self.ids,
            target,
            current: 0,
        }))
    }
}

/// Index of the input to focus among `count` listed inputs.
fn cycle_target(count: usize, focused: Option<usize>, forward: bool) -> Option<usize> {
    if count == 0 {
        return None;
    }
    Some(match (focused, forward) {
        (None, true) => 0,
        (None, false) => count - 1,
        (Some(i), true) => (i + 1) % count,
        (Some(i), false) => (i + count - 1) % count,
    })
}

/// Second pass of [`cycle`]: focuses the target, unfocuses everything else.
struct Apply {
    ids: &'static [&'static str],
    target: usize,
    current: usize,
}

impl Operation for Apply {
    fn focusable(&mut self, id: Option<&Id>, _bounds: Rectangle, state: &mut dyn Focusable) {
        if !is_listed(self.ids, id) {
            state.unfocus();
            return;
        }
        if self.current == self.target {
            state.focus();
        } else {
            state.unfocus();
        }
        self.current += 1;
    }

    fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation)) {
        operate(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Input {
        id: Option<Id>,
        focused: bool,
    }

    impl Focusable for Input {
        fn is_focused(&self) -> bool {
            self.focused
        }
        fn focus(&mut self) {
            self.focused = true;
        }
        fn unfocus(&mut self) {
            self.focused = false;
        }
    }

    fn input(id: Option<&'static str>, focused: bool) -> Input {
        Input {
            id: id.map(Id::new),
            focused,
        }
    }

    /// Runs `operation` (and its chained follow-ups) over `inputs` in order.
    fn run(mut operation: Box<dyn Operation>, inputs: &mut [Input]) {
        loop {
            for input in inputs.iter_mut() {
                let id = input.id.clone();
                operation.focusable(id.as_ref(), Rectangle::default(), input);
            }
            match operation.finish() {
                Outcome::Chain(next) => operation = next,
                Outcome::None | Outcome::Some(()) => return,
            }
        }
    }

    fn scan(ids: &'static [&'static str], forward: bool) -> Box<dyn Operation> {
        Box::new(Scan {
            ids,
            forward,
            seen: 0,
            focused: None,
        })
    }

    fn focused(inputs: &[Input]) -> Vec<bool> {
        inputs.iter().map(|i| i.focused).collect()
    }

    const LAYER: &[&str] = &["a", "b", "c"];

    #[test]
    fn test_tab_cycles_within_the_listed_inputs_only() {
        // "hidden" belongs to a layer beneath the modal; it is skipped
        let mut inputs = [
            input(Some("hidden"), false),
            input(Some("a"), false),
            input(None, false),
            input(Some("b"), false),
            input(Some("c"), false),
        ];
        run(scan(LAYER, true), &mut inputs);
        assert_eq!(focused(&inputs), [false, true, false, false, false]);
        run(scan(LAYER, true), &mut inputs);
        assert_eq!(focused(&inputs), [false, false, false, true, false]);
        run(scan(LAYER, true), &mut inputs);
        run(scan(LAYER, true), &mut inputs);
        assert_eq!(
            focused(&inputs),
            [false, true, false, false, false],
            "wraps around"
        );
        // Shift+Tab goes back, wrapping too
        run(scan(LAYER, false), &mut inputs);
        assert_eq!(focused(&inputs), [false, false, false, false, true]);
    }

    #[test]
    fn test_tab_takes_focus_from_a_hidden_input() {
        let mut inputs = [input(Some("hidden"), true), input(Some("a"), false)];
        run(scan(LAYER, false), &mut inputs);
        assert_eq!(focused(&inputs), [false, true]);
    }

    #[test]
    fn test_tab_without_listed_inputs_changes_nothing() {
        let mut inputs = [input(Some("hidden"), true)];
        run(scan(LAYER, true), &mut inputs);
        assert_eq!(focused(&inputs), [true]);
    }

    #[test]
    fn test_cycle_target() {
        assert_eq!(cycle_target(0, None, true), None);
        assert_eq!(cycle_target(3, None, true), Some(0));
        assert_eq!(cycle_target(3, None, false), Some(2));
        assert_eq!(cycle_target(3, Some(2), true), Some(0));
        assert_eq!(cycle_target(3, Some(0), false), Some(2));
    }
}
