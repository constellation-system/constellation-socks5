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

//! SOCKS5 protocol state machine implementation.
//!
//! This module contains an implementation of the SOCKS5 protocol
//! state machine, using the
//! [RawMachineState](constellation_streams::state_machine::RawStateMachine)
//! framework.  This can be set up and run to completion, yielding a
//! [SOCKS5Result] that can in turn be used to instantiate a
//! [SOCKS5Stream] or [SOCKS5UDPXfrm].
use std::fmt::Debug;
use std::fmt::Formatter;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
#[cfg(feature = "gssapi")]
use std::sync::Arc;
#[cfg(feature = "gssapi")]
use std::sync::Mutex;

use constellation_common::net::DatagramXfrm;
use constellation_common::net::IPEndpoint;
use constellation_streams::state_machine::OnceMachineAction;
use constellation_streams::state_machine::RawMachineState;
use constellation_streams::state_machine::RawOnceMachineState;
#[cfg(feature = "gssapi")]
use libgssapi::context::ClientCtx;
#[cfg(feature = "gssapi")]
use libgssapi::util::Buf;
#[cfg(feature = "log")]
use log::debug;
#[cfg(feature = "log")]
use log::error;
#[cfg(feature = "log")]
#[cfg(feature = "gssapi")]
use log::trace;
#[cfg(feature = "log")]
use log::warn;

use crate::comm::SOCKS5Stream;
use crate::comm::SOCKS5UDPXfrm;
use crate::error::SOCKS5Error;
use crate::params::SOCKS5Params;
use crate::proto;
use crate::proto::AuthNMech;

/// SOCKS5 protocol state machine states.
///
/// This also functions as the primary state machine object.  These
/// states should generally not be instantiated directly; use
/// [start](RawMachineState::start) to create an instance.
pub enum SOCKS5State {
    /// Send authentication methods and read server's selection.
    AuthNMethods,
    #[cfg(feature = "gssapi")]
    /// GSSAPI auhentication.
    GSSAPIAuthN {
        /// GSSAPI context.
        ctx: ClientCtx,
        /// Buffered message to write.
        msg: Buf
    },
    #[cfg(feature = "gssapi")]
    /// GSSAPI security level negotiation.
    GSSAPISecLvl {
        /// GSSAPI context.
        ctx: ClientCtx
    },
    /// Send username and password, read reply.
    PasswordAuthN,
    /// Send command, read reply.
    Command {
        #[cfg(feature = "gssapi")]
        /// Possible GSSAPI context.
        ctx: Option<ClientCtx>
    },
    /// Success end-state.
    Success {
        /// Protocol result.
        result: SOCKS5Result
    },
    /// Error end-state.
    Error {
        /// The protocol error.
        error: SOCKS5Error
    }
}

/// Result of the SOCKS5 protocol.
///
/// This can be used to instantiate a [SOCKS5Stream] using
/// [wrap_stream](SOCKS5Result::wrap_stream).  It can also be used to
/// obtain a [SOCKS5UDPInfo] using [udp_info](SOCKS5Result::udp_info).
pub struct SOCKS5Result {
    /// Endpoint reported by proxy.
    endpoint: IPEndpoint,
    #[cfg(feature = "gssapi")]
    /// Possible GSSAPI context.
    ctx: Option<ClientCtx>
}

/// Information about a SOCKS5 UDP association.
///
/// This object is used to create [SOCKS5UDPXfrm] instances
/// suitable for encapsulating UDP traffic.  It is separate from the
/// underlying socket connection, and contains the GSSAPI context, if
/// there is one.
pub struct SOCKS5UDPInfo {
    /// Endpoint reported by proxy.
    endpoint: IPEndpoint,
    #[cfg(feature = "gssapi")]
    /// Possible GSSAPI context.
    ctx: Option<Arc<Mutex<ClientCtx>>>
}

impl Debug for SOCKS5Result {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        write!(f, "SOCKS5Result {{ endpoint: {} }}", self.endpoint)
    }
}

impl Debug for SOCKS5UDPInfo {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        write!(f, "SOCKS5UDPInfo {{ endpoint: {} }}", self.endpoint)
    }
}

impl SOCKS5Result {
    /// Get the IP endpoint.
    #[inline]
    pub fn ip_endpoint(&self) -> &IPEndpoint {
        &self.endpoint
    }

    #[cfg(feature = "gssapi")]
    /// Wrap a stream to obtain a SOCKS5Stream.
    ///
    /// Consumes this `SOCKS5Result` to combine with `stream` to
    /// produce a [SOCKS5Stream].  The underlying SOCKS5 connection
    /// will then be closed when the return result is dropped.
    #[inline]
    pub fn wrap_stream<Stream>(
        self,
        stream: Stream
    ) -> SOCKS5Stream<Stream>
    where
        Stream: Read + Write {
        match self.ctx {
            Some(ctx) => SOCKS5Stream::GSSAPI {
                ctx: ctx,
                stream: stream
            },
            None => SOCKS5Stream::Passthru { stream: stream }
        }
    }

    #[cfg(not(feature = "gssapi"))]
    /// Wrap a stream to obtain a SOCKS5Stream.
    ///
    /// Consumes this `SOCKS5Result` to combine with `stream` to
    /// produce a [SOCKS5Stream].  The underlying SOCKS5 connection
    /// will then be closed when the return result is dropped.
    #[inline]
    pub fn wrap_stream<Stream>(
        self,
        stream: Stream
    ) -> SOCKS5Stream<Stream>
    where
        Stream: Read + Write {
        SOCKS5Stream::Passthru { stream: stream }
    }

    /// Get information to create a UDP context.
    ///
    /// Consumes this `SOCKS5Result` to produce a [SOCKS5UDPInfo],
    /// which can then be used to create a [SOCKS5UDPXfrm].
    #[inline]
    pub fn udp_info(self) -> SOCKS5UDPInfo {
        SOCKS5UDPInfo {
            #[cfg(feature = "gssapi")]
            ctx: self.ctx.map(|c| Arc::new(Mutex::new(c))),
            endpoint: self.endpoint
        }
    }
}

impl SOCKS5UDPInfo {
    /// Get the IP endpoint.
    #[inline]
    pub fn ip_endpoint(&self) -> &IPEndpoint {
        &self.endpoint
    }

    #[cfg(feature = "gssapi")]
    /// Create a [SOCKS5UDPXfrm] to use.
    ///
    /// This creates the [DatagramXfrm] instance used to
    /// encapsulate UDP packets for sending over the SOCKS5 channel.
    #[inline]
    pub fn udp_xfrm<Inner>(
        &self,
        proxy: Inner::PeerAddr,
        inner: Inner
    ) -> SOCKS5UDPXfrm<Inner>
    where
        Inner: DatagramXfrm {
        match &self.ctx {
            Some(ctx) => SOCKS5UDPXfrm::GSSAPI {
                proxy: proxy,
                inner: inner,
                ctx: ctx.clone()
            },
            None => SOCKS5UDPXfrm::Basic {
                proxy: proxy,
                inner: inner
            }
        }
    }

    #[cfg(not(feature = "gssapi"))]
    /// Create a [SOCKS5UDPXfrm] to use.
    ///
    /// This creates the [DatagramXfrm] instance used to
    /// encapsulate UDP packets for sending over the SOCKS5 channel.
    #[inline]
    pub fn udp_xfrm<Inner>(
        &self,
        proxy: Inner::PeerAddr,
        inner: Inner
    ) -> SOCKS5UDPXfrm<Inner>
    where
        Inner: DatagramXfrm {
        SOCKS5UDPXfrm::Basic {
            proxy: proxy,
            inner: inner
        }
    }
}

impl RawMachineState for SOCKS5State {
    type Error = SOCKS5Error;
    type Params = SOCKS5Params;
    type Value = SOCKS5Result;

    #[inline]
    fn start(_params: &SOCKS5Params) -> SOCKS5State {
        SOCKS5State::AuthNMethods
    }

    #[inline]
    fn error(
        _params: &SOCKS5Params,
        error: SOCKS5Error
    ) -> SOCKS5State {
        SOCKS5State::Error { error: error }
    }

    #[inline]
    fn write<W>(
        &mut self,
        params: &SOCKS5Params,
        stream: &mut W
    ) -> Result<(), SOCKS5Error>
    where
        W: Write {
        match self {
            // Send authentication methods.
            #[cfg(feature = "gssapi")]
            SOCKS5State::AuthNMethods => proto::write_authn_methods(
                stream,
                params.gssapi().is_some(),
                params.password().is_some()
            )
            .map_err(|err| SOCKS5Error::IOError { error: err }),
            #[cfg(not(feature = "gssapi"))]
            SOCKS5State::AuthNMethods => {
                proto::write_authn_methods(stream, params.password().is_some())
                    .map_err(|err| SOCKS5Error::IOError { error: err })
            }
            // Send command.
            SOCKS5State::Command {
                #[cfg(feature = "gssapi")]
                ctx
            } => {
                #[cfg(feature = "log")]
                debug!(target: "socks5-protocol",
                       "sending command to proxy ({} to {})",
                       params.cmd(), params.target());

                proto::write_cmd(
                    stream,
                    #[cfg(feature = "gssapi")]
                    ctx.as_mut(),
                    *params.cmd() as u8,
                    params.target()
                )
            }
            // Send password authentication info.
            SOCKS5State::PasswordAuthN => match params.password() {
                // Get the config information and write it out.
                Some(password) => proto::write_password_authn(
                    stream,
                    password.username(),
                    password.password()
                ),
                // This should never happen
                None => {
                    #[cfg(feature = "log")]
                    error!(target: "socks5-protocol",
                           concat!("internal error, in password authn state",
                                   "but no config is present"));

                    Err(SOCKS5Error::IOError {
                        error: Error::new(
                            ErrorKind::Other,
                            "internal state machine error"
                        )
                    })
                }
            },
            #[cfg(feature = "gssapi")]
            // Send GSSAPI authentication step.
            SOCKS5State::GSSAPIAuthN { msg, .. } => {
                proto::write_gssapi_step(stream, msg)
            }
            #[cfg(feature = "gssapi")]
            // Send GSSAPI security level request.
            SOCKS5State::GSSAPISecLvl { ctx } => match params.gssapi() {
                Some(gssapi) => proto::write_gssapi_seclvl(
                    stream,
                    ctx,
                    gssapi.security().seclvl()
                ),
                None => {
                    // This should never happen.
                    #[cfg(feature = "log")]
                    error!(target: "socks5-protocol",
                           concat!("internal error, in GSSAPI seclvl state",
                                   "but no config is present"));

                    Err(SOCKS5Error::IOError {
                        error: Error::new(
                            ErrorKind::Other,
                            "internal state machine error"
                        )
                    })
                }
            },
            _ => Ok(())
        }
    }

    fn read_select<R>(
        self,
        _params: &SOCKS5Params,
        stream: &mut R
    ) -> Result<Self, SOCKS5Error>
    where
        R: Read {
        match self {
            SOCKS5State::AuthNMethods => match proto::parse_method(stream)? {
                // No authentication; go straight to command.
                AuthNMech::None => {
                    #[cfg(feature = "log")]
                    debug!(target: "socks5-protocol",
                           "proxy requested no authentication");

                    Ok(SOCKS5State::Command {
                        #[cfg(feature = "gssapi")]
                        ctx: None
                    })
                }
                // GSSAPI authentication selected.
                #[cfg(feature = "gssapi")]
                AuthNMech::GSSAPI => match _params.gssapi() {
                    Some(gssapi) => {
                        // Prepare a GSSAPI state.
                        #[cfg(feature = "log")]
                        debug!(target: "socks5-protocol",
                               "proxy requested GSSAPI authentication");
                        let mut ctx = proto::prepare_gssapi(gssapi)?;

                        // Do the first step.
                        match ctx.step(None, gssapi.bindings()) {
                            // The step returned a message.  Continue
                            // authnenticating.
                            Ok(Some(msg)) => {
                                #[cfg(feature = "log")]
                                trace!(target: "socks5-protocol",
                                       "continuing GSSAPI authentication");

                                Ok(SOCKS5State::GSSAPIAuthN {
                                    msg: msg,
                                    ctx: ctx
                                })
                            }
                            // The step returned no message.  We're
                            // authenticated.
                            Ok(None) => {
                                #[cfg(feature = "log")]
                                debug!(target: "socks5-protocol",
                                       "GSSAPI authentication succeeded");

                                Ok(SOCKS5State::Command { ctx: Some(ctx) })
                            }
                            // The step returned an error.
                            Err(err) => {
                                Err(SOCKS5Error::GSSAPIError { error: err })
                            }
                        }
                    }
                    None => {
                        #[cfg(feature = "log")]
                        error!(target: "socks5-protocol",
                               concat!("proxy requested GSSAPI authentication,",
                                       " but this mechanism is not enabled"));

                        Err(SOCKS5Error::NoAuthNMethods)
                    }
                },
                // Password authentication selected.
                AuthNMech::Password => {
                    #[cfg(feature = "log")]
                    debug!(target: "socks5-protocol",
                           "proxy requested password authentication");

                    Ok(SOCKS5State::PasswordAuthN)
                }
            },
            // Read in a GSSAPI authentication message.
            #[cfg(feature = "gssapi")]
            SOCKS5State::GSSAPIAuthN { mut ctx, .. } => {
                match _params.gssapi() {
                    Some(gssapi) => {
                        // Read in the server message.
                        let token = proto::parse_gssapi_step(stream)?;

                        match ctx.step(Some(&token), gssapi.bindings()) {
                            // The step returned a message.  Continue
                            // authnenticating.
                            Ok(Some(msg)) => {
                                #[cfg(feature = "log")]
                                trace!(target: "socks5-protocol",
                                   "continuing GSSAPI authentication");

                                Ok(SOCKS5State::GSSAPIAuthN {
                                    msg: msg,
                                    ctx: ctx
                                })
                            }
                            // The step returned no message.  We're
                            // authenticated.
                            Ok(None) => {
                                #[cfg(feature = "log")]
                                debug!(target: "socks5-protocol",
                                   "GSSAPI authentication succeeded");

                                Ok(SOCKS5State::GSSAPISecLvl { ctx: ctx })
                            }
                            // The step returned an error.
                            Err(err) => {
                                Err(SOCKS5Error::GSSAPIError { error: err })
                            }
                        }
                    }
                    None => {
                        // This should never happen.
                        #[cfg(feature = "log")]
                        error!(target: "socks5-protocol",
                           concat!("internal error, in GSSAPI seclvl state",
                                   "but no config is present"));

                        Err(SOCKS5Error::IOError {
                            error: Error::new(
                                ErrorKind::Other,
                                "internal state machine error"
                            )
                        })
                    }
                }
            }
            #[cfg(feature = "gssapi")]
            // Send GSSAPI security level request.
            SOCKS5State::GSSAPISecLvl { mut ctx } => match _params.gssapi() {
                Some(gssapi) => {
                    let seclvl = proto::parse_gssapi_seclvl(stream, &mut ctx)?;

                    if !gssapi.security().is_required() ||
                        gssapi.security().seclvl() >= seclvl
                    {
                        Ok(SOCKS5State::Command {
                            #[cfg(feature = "gssapi")]
                            ctx: Some(ctx)
                        })
                    } else {
                        Err(SOCKS5Error::BadGSSAPISecLvl { seclvl: seclvl })
                    }
                }
                None => {
                    // This should never happen.
                    #[cfg(feature = "log")]
                    error!(target: "socks5-protocol",
                           concat!("internal error, in GSSAPI seclvl state",
                                   "but no config is present"));

                    Err(SOCKS5Error::IOError {
                        error: Error::new(
                            ErrorKind::Other,
                            "internal state machine error"
                        )
                    })
                }
            },
            // Read back the password authentication reply.
            SOCKS5State::PasswordAuthN => {
                match proto::parse_password_authn_reply(stream) {
                    // Authentication succeeded.
                    Ok(true) => {
                        #[cfg(feature = "log")]
                        debug!(target: "socks5-protocol",
                               "password authentication succeeded");

                        Ok(SOCKS5State::Command {
                            #[cfg(feature = "gssapi")]
                            ctx: None
                        })
                    }
                    // Authentication failed normally.
                    Ok(false) => {
                        #[cfg(feature = "log")]
                        error!(target: "socks5-protocol",
                               "password authentication failed");

                        Err(SOCKS5Error::AuthNFailed)
                    }
                    // Error reading authentication reply.
                    Err(err) => {
                        #[cfg(feature = "log")]
                        error!(target: "socks5-protocol",
                               concat!("error reading password ",
                                       "authentication reply ({})"),
                               err);

                        Err(err)
                    }
                }
            }
            // Read the command result.
            SOCKS5State::Command {
                #[cfg(feature = "gssapi")]
                mut ctx
            } => match proto::parse_reply(
                stream,
                #[cfg(feature = "gssapi")]
                ctx.as_mut()
            ) {
                // The command succeeded; we're done.
                Ok(endpoint) => {
                    #[cfg(feature = "log")]
                    debug!(target: "socks5-protocol",
                           "command succeeded with result value {}",
                           endpoint);

                    let result = SOCKS5Result {
                        endpoint: endpoint,
                        #[cfg(feature = "gssapi")]
                        ctx: ctx
                    };

                    Ok(SOCKS5State::Success { result: result })
                }
                // The command failed with an error.
                Err(err) => {
                    #[cfg(feature = "log")]
                    warn!(target: "socks5-protocol",
                          "command failed ({})",
                          err);

                    Err(err)
                }
            },
            // End states.
            end => Ok(end)
        }
    }
}

impl RawOnceMachineState for SOCKS5State {
    #[inline]
    fn end(
        self,
        _params: &SOCKS5Params
    ) -> OnceMachineAction<Self, Result<SOCKS5Result, SOCKS5Error>> {
        match self {
            SOCKS5State::Success { result } => {
                #[cfg(feature = "log")]
                debug!(target: "socks5-protocol",
                       "SOCKS5 protocol has reached an end state");

                OnceMachineAction::Stop(Ok(result))
            }
            SOCKS5State::Error { error } => {
                #[cfg(feature = "log")]
                debug!(target: "socks5-protocol",
                       "terminating SOCKS5 protocol with error ({})",
                       error);

                OnceMachineAction::Stop(Err(error))
            }
            out => OnceMachineAction::Continue(out)
        }
    }
}

#[cfg(test)]
use std::collections::VecDeque;
#[cfg(test)]
use std::net::IpAddr;

#[cfg(test)]
use constellation_common::net::IPEndpointAddr;
#[cfg(test)]
use constellation_streams::state_machine::RawStateMachine;

#[cfg(test)]
use crate::init;

#[cfg(test)]
struct DoubleDeque {
    uplink: VecDeque<u8>,
    downlink: VecDeque<u8>
}

#[cfg(test)]
impl Read for DoubleDeque {
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        self.downlink.read(buf)
    }
}

#[cfg(test)]
impl Write for DoubleDeque {
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        self.uplink.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        self.uplink.flush()
    }
}

#[test]
fn test_no_auth_bad_auth_mechs() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_no_auth(endpoint);
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0xff]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x01, 0x00];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::NoAuthNMethods => {}
        err => panic!("Expected {}, got {}", SOCKS5Error::NoAuthNMethods, err)
    }
}

#[test]
fn test_password_auth_bad_auth_mechs() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_password_auth(
        endpoint,
        String::from("user"),
        String::from("pass")
    );
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0xff]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x02, 0x00, 0x02];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::NoAuthNMethods => {}
        err => panic!("Expected {}, got {}", SOCKS5Error::NoAuthNMethods, err)
    }
}

#[test]
fn test_password_auth_fail() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_password_auth(
        endpoint,
        String::from("user"),
        String::from("pass")
    );
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x02]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x02, 0x00, 0x02];

    assert_eq!(&msg, &expected);

    // Step: send password, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0xff]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x04, 0x75, 0x73, 0x65, 0x72, 0x04, 0x70, 0x61, 0x73, 0x73
    ];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::AuthNFailed => {}
        err => panic!("Expected {}, got {}", SOCKS5Error::AuthNFailed, err)
    }
}

#[test]
fn test_no_auth_connect_server_fail() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_no_auth(endpoint);
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x01, 0x00];

    assert_eq!(&msg, &expected);

    // Step: send connect, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::ServerFailure => {}
        err => panic!("Expected {}, got {}", SOCKS5Error::ServerFailure, err)
    }
}

#[test]
fn test_no_auth_connect_permission_denied() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_no_auth(endpoint);
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x01, 0x00];

    assert_eq!(&msg, &expected);

    // Step: send connect, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x02, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::PermissionDenied => {}
        err => panic!("Expected {}, got {}", SOCKS5Error::PermissionDenied, err)
    }
}

#[test]
fn test_no_auth_connect_net_unreachable() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_no_auth(endpoint);
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x01, 0x00];

    assert_eq!(&msg, &expected);

    // Step: send connect, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x03, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::NetworkUnreachable => {}
        err => {
            panic!("Expected {}, got {}", SOCKS5Error::NetworkUnreachable, err)
        }
    }
}

#[test]
fn test_no_auth_connect_host_unreachable() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_no_auth(endpoint);
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x01, 0x00];

    assert_eq!(&msg, &expected);

    // Step: send connect, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x04, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::HostUnreachable => {}
        err => panic!("Expected {}, got {}", SOCKS5Error::HostUnreachable, err)
    }
}

#[test]
fn test_no_auth_connect_connection_refused() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_no_auth(endpoint);
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x01, 0x00];

    assert_eq!(&msg, &expected);

    // Step: send connect, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x05, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::ConnectionRefused => {}
        err => {
            panic!("Expected {}, got {}", SOCKS5Error::ConnectionRefused, err)
        }
    }
}

#[test]
fn test_no_auth_connect_ttl_expired() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_no_auth(endpoint);
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x01, 0x00];

    assert_eq!(&msg, &expected);

    // Step: send connect, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x06, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::TTLExpired => {}
        err => panic!("Expected {}, got {}", SOCKS5Error::TTLExpired, err)
    }
}

#[test]
fn test_no_auth_connect_cmd_not_supported() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_no_auth(endpoint);
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x01, 0x00];

    assert_eq!(&msg, &expected);

    // Step: send connect, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x07, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::CmdNotSupported => {}
        err => panic!("Expected {}, got {}", SOCKS5Error::CmdNotSupported, err)
    }
}

#[test]
fn test_no_auth_connect_addr_not_supported() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_no_auth(endpoint);
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x01, 0x00];

    assert_eq!(&msg, &expected);

    // Step: send connect, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x08, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::AddrTypeNotSupported => {}
        err => panic!(
            "Expected {}, got {}",
            SOCKS5Error::AddrTypeNotSupported,
            err
        )
    }
}

#[test]
fn test_password_auth_connect_fail() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_password_auth(
        endpoint,
        String::from("user"),
        String::from("pass")
    );
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x02]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x02, 0x00, 0x02];

    assert_eq!(&msg, &expected);

    // Step: send password, get success.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x04, 0x75, 0x73, 0x65, 0x72, 0x04, 0x70, 0x61, 0x73, 0x73
    ];

    assert_eq!(&msg, &expected);

    // Step: send connect, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see error
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end,
        _ => panic!("Should request to stop here")
    };

    match res.err().expect("Expected error") {
        SOCKS5Error::ServerFailure => {}
        err => panic!("Expected {}, got {}", SOCKS5Error::ServerFailure, err)
    }
}

#[test]
fn test_no_auth_connect_succeed() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_no_auth(endpoint);
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x01, 0x00];

    assert_eq!(&msg, &expected);

    // Step: send connect, get success.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see success.
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end.expect("Expected success"),
        _ => panic!("Should request to stop here")
    };

    let ip = IPEndpointAddr::ip(IpAddr::from([0x01, 0x02, 0x03, 0x04]));
    let port = 0x1337;

    assert_eq!(res.endpoint, IPEndpoint::new(ip, port));
}

#[test]
fn test_password_auth_connect_succeed() {
    init();

    let mut link = DoubleDeque {
        uplink: VecDeque::with_capacity(2),
        downlink: VecDeque::with_capacity(2)
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let params = SOCKS5Params::connect_password_auth(
        endpoint,
        String::from("user"),
        String::from("pass")
    );
    let machine: RawStateMachine<SOCKS5State> = RawStateMachine::new(params);

    // Step: send authn mechs, get no mechs response.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x02]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [0x05, 0x02, 0x00, 0x02];

    assert_eq!(&msg, &expected);

    // Step: send password, get success.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink.write(&[0x05, 0x00]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x04, 0x75, 0x73, 0x65, 0x72, 0x04, 0x70, 0x61, 0x73, 0x73
    ];

    assert_eq!(&msg, &expected);

    // Step: send connect, get failure.
    let mut machine = match machine.end() {
        OnceMachineAction::Continue(machine) => machine,
        _ => panic!("Should not request to stop here")
    };

    link.downlink
        .write(&[0x05, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37]);
    machine.step(&mut link);

    let msg: Vec<u8> = link.uplink.drain(..).collect();
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    assert_eq!(&msg, &expected);

    // End: should see success.
    let res = match machine.end() {
        OnceMachineAction::Stop(end) => end.expect("Expected success"),
        _ => panic!("Should request to stop here")
    };

    let ip = IPEndpointAddr::ip(IpAddr::from([0x01, 0x02, 0x03, 0x04]));
    let port = 0x1337;

    assert_eq!(res.endpoint, IPEndpoint::new(ip, port));
}
