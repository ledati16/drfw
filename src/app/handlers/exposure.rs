//! Exposure panel handlers: open/close, scan and refresh
//!
//! The socket scan reads `/proc` and is run on the blocking pool, never on
//! the UI thread. It also finds the SSH sessions (kept in
//! `State::ssh_sessions` for the lockout check). Results carry the generation of their request; a result
//! for a closed panel or an older request is ignored.

use iced::Task;

use crate::app::exposure::{ExposurePanel, ExposureScan};
use crate::app::{Message, State};

/// User-facing message when the sockets cannot be read.
const SCAN_FAILED: &str = "Could not read the list of listening sockets.";

/// Opens (and scans) or closes the Exposure panel.
pub(crate) fn handle_toggle_exposure(state: &mut State, show: bool) -> Task<Message> {
    if !show {
        state.exposure.panel = None;
        return Task::none();
    }
    if state.exposure.panel.is_some() {
        return Task::none();
    }
    state.exposure.panel = Some(ExposurePanel::scanning());
    start_scan(state)
}

/// Re-reads the listening sockets (the Refresh button).
pub(crate) fn handle_refresh_exposure(state: &mut State) -> Task<Message> {
    let Some(panel) = &mut state.exposure.panel else {
        return Task::none();
    };
    panel.scanning = true;
    start_scan(state)
}

/// A scan finished: store it if it is the latest one for the open panel.
pub(crate) fn handle_exposure_scanned(
    state: &mut State,
    generation: u64,
    result: Result<ExposureScan, String>,
) {
    if generation != state.exposure.generation {
        return;
    }
    if let Ok(scan) = &result {
        state.ssh_sessions.clone_from(&scan.sessions);
    }
    let Some(panel) = &mut state.exposure.panel else {
        return;
    };
    panel.set_scan(result, &state.ruleset, state.last_applied_ruleset.as_ref());
}

/// Reads the sockets and SSH sessions (blocking): `env` is the
/// `SSH_CONNECTION` session of this process.
fn scan_blocking(env: Option<crate::core::lockout::SshSession>) -> std::io::Result<ExposureScan> {
    let host = crate::core::exposure::scan_host()?;
    let sessions = crate::core::lockout::with_interfaces(crate::core::lockout::merge_sessions(
        env,
        crate::core::lockout::sessions_from_scan(&host),
    ));
    Ok(ExposureScan {
        sockets: host.sockets,
        sessions,
    })
}

/// Starts a scan on the blocking pool under a new generation.
fn start_scan(state: &mut State) -> Task<Message> {
    state.exposure.generation = state.exposure.generation.wrapping_add(1);
    let generation = state.exposure.generation;
    let env = state.ssh_env_session.clone();
    Task::perform(
        async move {
            match tokio::task::spawn_blocking(move || scan_blocking(env)).await {
                Ok(Ok(scan)) => Ok(scan),
                Ok(Err(e)) => {
                    tracing::warn!("Listening socket scan failed: {e}");
                    Err(SCAN_FAILED.to_string())
                }
                Err(e) => {
                    tracing::error!("Listening socket scan panicked: {e}");
                    Err(SCAN_FAILED.to_string())
                }
            }
        },
        move |result| Message::ExposureScanned(generation, result),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::handlers::test_utils::create_test_state;

    #[test]
    fn test_open_scans_and_close_drops_the_panel() {
        let mut state = create_test_state();
        let _ = handle_toggle_exposure(&mut state, true);
        let panel = state.exposure.panel.as_ref().expect("open");
        assert!(panel.scanning);
        let generation = state.exposure.generation;

        handle_exposure_scanned(&mut state, generation, Ok(ExposureScan::default()));
        let panel = state.exposure.panel.as_ref().expect("open");
        assert!(!panel.scanning);
        assert_eq!(panel.summary, "No listening sockets found.");

        let _ = handle_toggle_exposure(&mut state, false);
        assert!(state.exposure.panel.is_none());
        // A late result for the closed panel is ignored
        handle_exposure_scanned(&mut state, generation, Ok(ExposureScan::default()));
        assert!(state.exposure.panel.is_none());
    }

    /// The scan's SSH sessions become the known ones (for the lockout
    /// check) and the panel's "SSH:" lines.
    #[test]
    fn test_scan_stores_ssh_sessions() {
        let mut state = create_test_state();
        let _ = handle_toggle_exposure(&mut state, true);
        let session =
            crate::core::lockout::parse_ssh_connection("10.0.0.5 50000 10.0.0.1 22").unwrap();
        let generation = state.exposure.generation;
        handle_exposure_scanned(
            &mut state,
            generation,
            Ok(ExposureScan {
                sockets: Vec::new(),
                sessions: vec![session.clone()],
            }),
        );
        assert_eq!(state.ssh_sessions, [session]);
        let panel = state.exposure.panel.as_ref().expect("open");
        assert_eq!(panel.ssh_lines.len(), 1);
        assert!(panel.ssh_lines[0].warning, "no rule allows port 22");
    }

    #[test]
    fn test_stale_scan_results_are_ignored() {
        let mut state = create_test_state();
        let _ = handle_toggle_exposure(&mut state, true);
        let first = state.exposure.generation;
        let _ = handle_refresh_exposure(&mut state);
        assert_ne!(first, state.exposure.generation);
        handle_exposure_scanned(&mut state, first, Err("old".into()));
        let panel = state.exposure.panel.as_ref().expect("open");
        assert!(panel.scanning, "still waiting for the latest scan");
        assert!(panel.error.is_none());
        let latest = state.exposure.generation;
        handle_exposure_scanned(&mut state, latest, Err(SCAN_FAILED.into()));
        let panel = state.exposure.panel.as_ref().expect("open");
        assert_eq!(panel.error.as_deref(), Some(SCAN_FAILED));
    }

    #[test]
    fn test_rows_follow_ruleset_changes_while_open() {
        use crate::core::evaluate::Transport;
        use crate::core::exposure::{ListeningSocket, build_socket_list};

        let mut state = create_test_state();
        let _ = handle_toggle_exposure(&mut state, true);
        let sockets = build_socket_list(
            vec![ListeningSocket {
                transport: Transport::Tcp,
                ipv6_socket: false,
                local: "0.0.0.0".parse().unwrap(),
                port: 2222,
                uid: 1000,
                inode: 1,
            }],
            &std::collections::HashMap::new(),
            1000,
            false,
            |_| None,
        );
        let latest = state.exposure.generation;
        handle_exposure_scanned(
            &mut state,
            latest,
            Ok(ExposureScan {
                sockets,
                sessions: Vec::new(),
            }),
        );
        let row = |state: &State| state.exposure.panel.as_ref().unwrap().rows[0].clone();
        assert!(!row(&state).highlight);

        let mut rule = crate::core::test_helpers::create_test_rule("ssh", Some(2222));
        rule.rebuild_caches();
        state.ruleset.rules.push(rule);
        state.update_cached_text();
        assert!(row(&state).highlight, "re-evaluated on the ruleset change");
        assert_eq!(row(&state).editor.text, "Reachable from: everyone");
    }
}
