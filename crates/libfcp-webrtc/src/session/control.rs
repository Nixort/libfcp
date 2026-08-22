// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! FCP control-channel installation, event pump and candidate staging helpers.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn emit_or_stage_candidate(shared: &Shared, sequence: u32, candidate: Vec<u8>) {
    let signal = {
        let Ok(connection) = shared.connection.lock() else {
            return;
        };
        connection
            .candidate(&shared.signer, sequence, candidate.clone())
            .ok()
            .and_then(signal_from_action)
    };
    if let Some(signal) = signal {
        if let Ok(sender) = shared.signals.lock() {
            let _ = sender.try_send(signal);
        }
        return;
    }
    if let Ok(mut staged) = shared.staged_candidates.lock() {
        if staged.len() == MAX_STAGED_LOCAL_CANDIDATES {
            let _ = staged.pop_front();
        }
        staged.push_back((sequence, candidate));
    }
}

async fn emit_event(shared: &Shared, event: SessionEvent) -> bool {
    shared.events.send(event).await.is_ok()
}

pub(super) async fn emit_terminal(shared: &Shared, event: SessionEvent) -> bool {
    if shared
        .terminal
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return true;
    }
    emit_event(shared, event).await
}

async fn emit_signal(shared: &Shared, signal: SignalEvent) -> bool {
    let sender = match shared.signals.lock() {
        Ok(sender) => sender.clone(),
        Err(_) => return false,
    };
    sender.send(signal).await.is_ok()
}

fn signal_from_action(action: Action) -> Option<SignalEvent> {
    match action {
        Action::Send(envelope) => Some(SignalEvent::new(*envelope)),
        _ => None,
    }
}

pub(super) async fn install_local_control_channel(
    shared: Arc<Shared>,
    channel: Arc<dyn DataChannel>,
) {
    *shared.control.lock().await = Some(channel.clone());
    spawn_control_pump(shared, channel);
}

pub(super) async fn install_remote_control_channel(
    shared: Arc<Shared>,
    channel: Arc<dyn DataChannel>,
) {
    let Ok(label) = channel.label().await else {
        return;
    };
    let Ok(protocol) = channel.protocol().await else {
        return;
    };
    let Ok(ordered) = channel.ordered().await else {
        return;
    };
    let reliable = matches!(channel.max_packet_life_time().await, Ok(None))
        && matches!(channel.max_retransmits().await, Ok(None));
    if label != CONTROL_CHANNEL.label
        || protocol != CONTROL_CHANNEL.protocol
        || !ordered
        || !reliable
    {
        let _ = channel.close().await;
        return;
    }
    *shared.control.lock().await = Some(channel.clone());
    spawn_control_pump(shared, channel);
}

fn spawn_control_pump(shared: Arc<Shared>, channel: Arc<dyn DataChannel>) {
    tokio::spawn(async move {
        loop {
            match channel.poll().await {
                Some(DataChannelEvent::OnOpen) => {
                    let actions = {
                        let Ok(mut connection) = shared.connection.lock() else {
                            return;
                        };
                        match apply_event(&mut connection, AdapterEvent::Connected) {
                            Ok(actions) => actions,
                            Err(_) => return,
                        }
                    };
                    for action in actions {
                        match action {
                            Action::DeliverCfr { payload } => {
                                if !emit_event(&shared, SessionEvent::DeliverCfr { payload }).await
                                {
                                    return;
                                }
                            }
                            Action::Send(envelope) => {
                                if !Box::pin(emit_signal(&shared, SignalEvent::new(*envelope)))
                                    .await
                                {
                                    return;
                                }
                            }
                            _ => {}
                        }
                    }
                    if !emit_event(&shared, SessionEvent::Connected).await {
                        return;
                    }
                }
                Some(DataChannelEvent::OnMessage(message)) => {
                    let actions = {
                        let Ok(mut connection) = shared.connection.lock() else {
                            return;
                        };
                        match apply_event(
                            &mut connection,
                            AdapterEvent::ControlBinary(message.data.to_vec()),
                        ) {
                            Ok(actions) => actions,
                            Err(_) => return,
                        }
                    };
                    for action in actions {
                        match action {
                            Action::DeliverCfr { payload } => {
                                if !emit_event(&shared, SessionEvent::DeliverCfr { payload }).await
                                {
                                    return;
                                }
                            }
                            Action::Send(envelope) => {
                                if !Box::pin(emit_signal(&shared, SignalEvent::new(*envelope)))
                                    .await
                                {
                                    return;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Some(DataChannelEvent::OnClose) | None => {
                    let _ = emit_terminal(&shared, SessionEvent::Failed).await;
                    return;
                }
                _ => {}
            }
        }
    });
}
