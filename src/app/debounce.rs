//! One-shot debounce timers
//!
//! Debounced work (config autosave, profile autosave, slider audit entries)
//! used to be driven by 100 ms polling subscriptions, and every poll rebuilt
//! the whole view. Instead, each kind of work owns one [`Timer`]: at the end
//! of every `update()` an unarmed timer whose work is pending is armed with a
//! single `sleep` [`Task`] that fires once at the work's deadline
//! (see `State::arm_debounce_timers`).
//!
//! Each armed timer carries a generation number. When it fires, the handler
//! asks [`Timer::fire`] whether it is still the armed one; a cancelled
//! (stale) timer is a no-op. If the deadline moved while the timer slept
//! (more edits arrived), the handler does nothing and the end-of-update
//! arming starts one new timer for the remaining time, so a burst of edits
//! costs about one wake-up per debounce period instead of ten per second.

use std::time::{Duration, Instant};

use iced::Task;

use crate::app::Message;

/// The kinds of debounced work, one [`Timer`] each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerKind {
    /// Write the config file
    ConfigSave,
    /// Write the active profile
    ProfileSave,
    /// Write the audit entry for a slider/text setting that stopped changing
    SliderLog,
}

/// State of one debounce timer: at most one `sleep` task is armed at a time.
#[derive(Debug, Default)]
pub struct Timer {
    /// Generation of the armed (or last armed) timer
    generation: u64,
    /// A timer task with `generation` is sleeping
    armed: bool,
}

impl Timer {
    /// Arms the timer unless it is already armed.
    ///
    /// Returns the generation the new timer task must carry, or `None` if a
    /// timer is already sleeping (it re-checks the deadline when it fires).
    pub fn arm(&mut self) -> Option<u64> {
        if self.armed {
            return None;
        }
        self.generation += 1;
        self.armed = true;
        Some(self.generation)
    }

    /// A timer task fired. Returns `true` (and disarms) if it is the armed
    /// one; `false` for a stale (cancelled or superseded) timer, which must
    /// then do nothing.
    pub fn fire(&mut self, generation: u64) -> bool {
        if self.armed && generation == self.generation {
            self.armed = false;
            true
        } else {
            false
        }
    }

    /// Invalidates the armed timer (it becomes a no-op when it fires).
    pub fn cancel(&mut self) {
        if self.armed {
            self.generation += 1;
            self.armed = false;
        }
    }

    /// `true` while a timer task is sleeping.
    #[cfg(test)]
    pub fn is_armed(&self) -> bool {
        self.armed
    }
}

/// One [`Timer`] per [`TimerKind`].
#[derive(Debug, Default)]
pub struct Timers {
    config_save: Timer,
    profile_save: Timer,
    slider_log: Timer,
}

impl Timers {
    /// The timer for `kind`.
    pub fn get_mut(&mut self, kind: TimerKind) -> &mut Timer {
        match kind {
            TimerKind::ConfigSave => &mut self.config_save,
            TimerKind::ProfileSave => &mut self.profile_save,
            TimerKind::SliderLog => &mut self.slider_log,
        }
    }

    /// Invalidates every armed timer (used when the window closes and the
    /// pending work is flushed directly).
    pub fn cancel_all(&mut self) {
        self.config_save.cancel();
        self.profile_save.cancel();
        self.slider_log.cancel();
    }

    /// `true` while the timer for `kind` is sleeping.
    #[cfg(test)]
    pub fn is_armed(&self, kind: TimerKind) -> bool {
        match kind {
            TimerKind::ConfigSave => self.config_save.is_armed(),
            TimerKind::ProfileSave => self.profile_save.is_armed(),
            TimerKind::SliderLog => self.slider_log.is_armed(),
        }
    }
}

/// Time left until `deadline` (zero if it has passed).
pub fn remaining(deadline: Instant, now: Instant) -> Duration {
    deadline.saturating_duration_since(now)
}

/// A task that sleeps for `delay`, then reports that timer `generation` of
/// `kind` fired.
pub fn timer_task(kind: TimerKind, generation: u64, delay: Duration) -> Task<Message> {
    // The sleep is created inside the future, i.e. on the executor's tokio
    // runtime, not in update() (which may run outside a runtime context).
    Task::perform(async move { tokio::time::sleep(delay).await }, move |()| {
        Message::TimerFired(kind, generation)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm_only_once_until_fired() {
        let mut timer = Timer::default();
        let first = timer.arm().expect("first arm");
        assert!(timer.arm().is_none(), "already armed");
        assert!(timer.is_armed());
        assert!(timer.fire(first));
        assert!(!timer.is_armed());
        let second = timer.arm().expect("re-arm after firing");
        assert_ne!(first, second);
    }

    #[test]
    fn test_stale_generation_is_ignored() {
        let mut timer = Timer::default();
        let first = timer.arm().unwrap();
        assert!(timer.fire(first));
        let second = timer.arm().unwrap();
        // A late duplicate of the first timer must not disarm the second
        assert!(!timer.fire(first));
        assert!(timer.is_armed());
        assert!(timer.fire(second));
    }

    #[test]
    fn test_cancel_makes_armed_timer_stale() {
        let mut timer = Timer::default();
        let generation = timer.arm().unwrap();
        timer.cancel();
        assert!(!timer.is_armed());
        assert!(!timer.fire(generation), "cancelled timer is a no-op");
        // Cancelling an unarmed timer changes nothing
        timer.cancel();
        let next = timer.arm().unwrap();
        assert!(timer.fire(next));
    }

    #[test]
    fn test_remaining_saturates() {
        let now = Instant::now();
        let later = now + Duration::from_millis(300);
        assert_eq!(remaining(later, now), Duration::from_millis(300));
        assert_eq!(remaining(now, later), Duration::ZERO);
    }
}
