// Copyright © 2024 The Johns Hopkins Applied Physics Laboratory LLC.
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public License,
// version 3, as published by the Free Software Foundation.  If you
// would like to purchase a commercial license for this software, please
// contact APL’s Tech Transfer at 240-592-0817 or
// techtransfer@jhuapl.edu.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program.  If not, see
// <https://www.gnu.org/licenses/>.

//! SOCKS5 protocol implementation.
//!
//! This package implements the SOCKS5 protocol, as defined in RFCs
//! [1928](https://www.rfc-editor.org/rfc/rfc1928),
//! [1929](https://www.rfc-editor.org/rfc/rfc1929), and
//! [1961](https://www.rfc-editor.org/rfc/rfc1961).  The following
//! functionality is provided:
//!
//! * Setup and negotiation of SOCKS5 connections, including connect, bind, and
//!   UDP associate modes.
//!
//! * Password and GSSAPI authentication methods.
//!
//! * Stream ([Read](std::io::Read), [Write](std::io::Write)) and
//!   [DatagramXfrm](constellation_common::net::DatagramXfrm) instances for
//!   sending messages over negotiated connections.
//!
//! The following functionality is *not* implemented:
//!
//! * UDP fragmentation
//!
//! # Usage
//!
//! This package is designed around a protocol state-machine
//! abstraction.  The SOCKS5 negotiation process uses the abstraction
//! provided by
//! [RawMachineState](constellation_streams::state_machine::RawStateMachine)
//! to implement the process of establishing a connection.  Once that
//! is done, streams or
//! [DatagramXfrm](constellation_common::net::DatagramXfrm)s can
//! be used to communicate over the SOCKS5 connection.
//!
//! ## Establishing SOCKS5 Connections
//!
//! To create and use a SOCKS5 connection, the following procedure is useds:
//!
//! 1. Create a [SOCKS5Params](crate::params::SOCKS5Params) instance to
//!    configure the connection.
//!
//! 1. Instantiate a [SOCKS5State](crate::state::SOCKS5State) using the
//!    `SOCKS5Params`.
//!
//! 1. Run the `SOCKS5State` state machine to completion using
//!    [run](constellation_streams::state_machine::RawStateMachine::run).
//!
//! 1. Running the state machine in this manner will succeed and return a
//!    [SOCKS5Result](crate::state::SOCKS5Result), or else return an error.
//!
//! ## Using SOCKS5 Connections
//!
//! Once a connection has been negotiated and a
//! [SOCKS5Result](crate::state::SOCKS5Result) obtained, an
//! appropriate object must be created for communicating over the
//! proxied connection.  The process for this differs for TCP and UDP
//! modes:
//!
//! * **TCP**: When using the "connect" or "bind" modes, the resulting
//!   [SOCKS5Result](crate::state::SOCKS5Result) must be combined with the
//!   underlying stream using
//!   [wrap_stream](crate::state::SOCKS5Result::wrap_stream).  This will produce
//!   a stream that will transparently perform any
//!   encapsulation/de-encapsulation necessary.
//!
//! * **UDP**: When using the UDP associate mode, a
//!   [DatagramXfrm](constellation_common::net::DatagramXfrm) instance must be
//!   created to perform encapsulation/de-encapsulation and add appropriate
//!   headers.  Due to the multiplexing that is often necessary for UDP
//!   protocols, this is kept separate from the underlying stream.  To create a
//!   context the [udp_info](crate::state::SOCKS5Result::udp_info) function is
//!   used to obtain a [SOCKS5UDPInfo](crate::state::SOCKS5UDPInfo), which can
//!   then be used to create any number of context objects.
#![allow(clippy::redundant_field_names)]
#![allow(clippy::upper_case_acronyms)]
mod proto;

pub mod comm;
pub mod error;
pub mod params;
pub mod state;

#[cfg(test)]
use std::sync::Once;

#[cfg(test)]
use log::LevelFilter;

#[cfg(test)]
static INIT: Once = Once::new();

#[cfg(test)]
fn init() {
    INIT.call_once(|| {
        env_logger::builder()
            .is_test(true)
            .filter_level(LevelFilter::Trace)
            .init()
    })
}
