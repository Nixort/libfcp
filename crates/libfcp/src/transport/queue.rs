// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Queue-backed adapter for FFI and native event-loop boundaries.

use alloc::vec::Vec;
use core::convert::Infallible;
use libfcp_core::{CloseCode, ControlChannelConfig, WebRtcBinding};

use crate::transport::WebRtcAdapter;

/// A platform-neutral command emitted by [`CommandQueue`].
///
/// Desktop, JNI and Swift/Objective-C++ bindings drain commands and call their
/// chosen WebRTC engine. The queue never claims a connection is live; the engine
/// must report the corresponding adapter event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeCommand {
    /// Apply a signed opaque offer to the engine.
    ApplyOffer {
        /// Binding digest supplied by FCP core.
        binding: WebRtcBinding,
        /// Exact bounded engine description bytes.
        description: Vec<u8>,
    },
    /// Apply a signed opaque answer to the engine.
    ApplyAnswer {
        /// Binding digest supplied by FCP core.
        binding: WebRtcBinding,
        /// Exact bounded engine description bytes.
        description: Vec<u8>,
    },
    /// Add one signed opaque ICE candidate to the engine.
    AddCandidate {
        /// Sender-local diagnostic sequence number.
        sequence: u32,
        /// Exact bounded opaque candidate bytes.
        candidate: Vec<u8>,
    },
    /// Configure/open the FCP reliable ordered control data channel.
    OpenControlChannel {
        /// Required FCP channel configuration.
        configuration: ControlChannelConfig,
    },
    /// Close the engine peer connection.
    Close {
        /// Signed remote close reason.
        reason: CloseCode,
    },
}

/// A queue-backed adapter for desktop event loops and mobile FFI boundaries.
///
/// The application owns queue draining and must pass engine events back through
/// [`crate::transport::apply_event`]. The implementation is synchronous and does not choose
/// a runtime, socket stack, TURN server or device SDK.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CommandQueue {
    commands: Vec<NativeCommand>,
}

impl CommandQueue {
    /// Drains commands in their original FCP action order.
    pub fn take_commands(&mut self) -> Vec<NativeCommand> {
        core::mem::take(&mut self.commands)
    }
}

impl WebRtcAdapter for CommandQueue {
    type Error = Infallible;

    fn apply_offer(
        &mut self,
        binding: WebRtcBinding,
        description: &[u8],
    ) -> Result<(), Self::Error> {
        self.commands.push(NativeCommand::ApplyOffer {
            binding,
            description: description.to_vec(),
        });
        Ok(())
    }

    fn apply_answer(
        &mut self,
        binding: WebRtcBinding,
        description: &[u8],
    ) -> Result<(), Self::Error> {
        self.commands.push(NativeCommand::ApplyAnswer {
            binding,
            description: description.to_vec(),
        });
        Ok(())
    }

    fn add_candidate(&mut self, sequence: u32, candidate: &[u8]) -> Result<(), Self::Error> {
        self.commands.push(NativeCommand::AddCandidate {
            sequence,
            candidate: candidate.to_vec(),
        });
        Ok(())
    }

    fn open_control_channel(
        &mut self,
        configuration: ControlChannelConfig,
    ) -> Result<(), Self::Error> {
        self.commands
            .push(NativeCommand::OpenControlChannel { configuration });
        Ok(())
    }

    fn close(&mut self, reason: CloseCode) -> Result<(), Self::Error> {
        self.commands.push(NativeCommand::Close { reason });
        Ok(())
    }
}
