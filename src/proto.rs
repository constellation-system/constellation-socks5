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

//! Low-level protocol encoding functions.
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
#[cfg(feature = "gssapi")]
use std::sync::Arc;
#[cfg(feature = "gssapi")]
use std::sync::Mutex;

use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
#[cfg(feature = "gssapi")]
use libgssapi::context::ClientCtx;
#[cfg(feature = "gssapi")]
use libgssapi::context::CtxFlags;
#[cfg(feature = "gssapi")]
use libgssapi::context::SecurityContext;
#[cfg(feature = "gssapi")]
use libgssapi::credential::Cred;
#[cfg(feature = "gssapi")]
use libgssapi::credential::CredUsage;
#[cfg(feature = "gssapi")]
use libgssapi::name::Name;
#[cfg(feature = "gssapi")]
use libgssapi::oid::OidSet;
#[cfg(feature = "gssapi")]
use libgssapi::oid::GSS_MECH_KRB5;
#[cfg(feature = "gssapi")]
use libgssapi::oid::GSS_NT_HOSTBASED_SERVICE;
#[cfg(feature = "gssapi")]
use libgssapi::util::Buf;
#[cfg(feature = "log")]
use log::debug;
#[cfg(feature = "log")]
use log::error;
#[cfg(feature = "log")]
#[cfg(feature = "gssapi")]
use log::info;
#[cfg(feature = "log")]
use log::trace;
#[cfg(feature = "log")]
#[cfg(feature = "gssapi")]
use log::warn;

use crate::error::SOCKS5Error;
use crate::error::SOCKS5WrapError;
#[cfg(feature = "gssapi")]
use crate::params::SOCKS5GSSAPIParams;

const IPV4: u8 = 0x01;
const IPV6: u8 = 0x04;
const NAME: u8 = 0x03;
const VERSION: u8 = 0x05;
const CMD_SUCCESS: u8 = 0x00;

const NO_AUTH: u8 = 0x00;
#[cfg(feature = "gssapi")]
const GSSAPI: u8 = 0x01;
const PASSWORD: u8 = 0x02;
const NO_METHODS: u8 = 0xff;

const SERVER_ERROR: u8 = 0x01;
const NOT_ALLOWED: u8 = 0x02;
const NETWORK_UNREACHABLE: u8 = 0x03;
const HOST_UNREACHABLE: u8 = 0x04;
const CONNECTION_REFUSED: u8 = 0x05;
const TTL_EXPIRED: u8 = 0x06;
const CMD_NOT_SUPPORTED: u8 = 0x07;
const ADDR_NOT_SUPPORTED: u8 = 0x08;

#[cfg(feature = "gssapi")]
const GSSAPI_VERSION: u8 = 0x01;
#[cfg(feature = "gssapi")]
const GSSAPI_CTX_NEGOTIATE: u8 = 0x01;
#[cfg(feature = "gssapi")]
const GSSAPI_CTX_NEGOTIATE_ERROR: u8 = 0xff;
#[cfg(feature = "gssapi")]
const GSSAPI_SECLVL_NEGOTIATE: u8 = 0x02;
#[cfg(feature = "gssapi")]
const GSSAPI_PAYLOAD: u8 = 0x03;

/// SOCKS5 authentication mechanism.
///
/// This indicates which SOCKS5 authentication mechanism to use.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthNMech {
    /// No authentication.
    None,
    #[cfg(feature = "gssapi")]
    /// GSSAPI authentication.
    GSSAPI,
    /// Password authentication.
    Password
}

#[cfg(feature = "gssapi")]
/// Write authentication methods.
///
/// This writes out the first client protocol message, stating the
/// available authentication methods.
#[inline]
pub fn write_authn_methods<S>(
    stream: &mut S,
    gssapi: bool,
    password: bool
) -> Result<(), Error>
where
    S: Write {
    #[cfg(feature = "log")]
    trace!(target: "socks5-protocol",
           "sending authn methods (gssapi: {}, password: {})",
           gssapi, password);

    match (gssapi, password) {
        (false, false) => stream.write_all(&[VERSION, 1, NO_AUTH]),
        (true, false) => stream.write_all(&[VERSION, 2, NO_AUTH, GSSAPI]),
        (false, true) => stream.write_all(&[VERSION, 2, NO_AUTH, PASSWORD]),
        (true, true) => {
            stream.write_all(&[VERSION, 3, NO_AUTH, GSSAPI, PASSWORD])
        }
    }
}

#[cfg(not(feature = "gssapi"))]
/// Write authentication methods.
///
/// This writes out the first client protocol message, stating the
/// available authentication methods.
#[inline]
pub fn write_authn_methods<S>(
    stream: &mut S,
    password: bool
) -> Result<(), Error>
where
    S: Write {
    #[cfg(feature = "log")]
    trace!(target: "socks5-protocol",
           "sending authn methods (password: {})",
           password);

    if password {
        stream.write_all(&[VERSION, 2, NO_AUTH, PASSWORD])
    } else {
        stream.write_all(&[VERSION, 1, NO_AUTH])
    }
}

/// Parse authentication method request from server.
#[inline]
pub fn parse_method<S>(stream: &mut S) -> Result<AuthNMech, SOCKS5Error>
where
    S: Read {
    #[cfg(feature = "log")]
    trace!(target: "socks5-protocol",
           "parsing authn method");

    let mut buf = [0; 2];

    stream
        .read_exact(&mut buf[..])
        .map_err(|err| SOCKS5Error::IOError { error: err })?;

    if buf[0] == 0x05 {
        match buf[1] {
            NO_AUTH => Ok(AuthNMech::None),
            #[cfg(feature = "gssapi")]
            GSSAPI => Ok(AuthNMech::GSSAPI),
            PASSWORD => Ok(AuthNMech::Password),
            NO_METHODS => {
                #[cfg(feature = "log")]
                error!(target: "socks5-protocol",
                       "proxy reported no acceptable authentication methods");

                Err(SOCKS5Error::NoAuthNMethods)
            }
            method => Err(SOCKS5Error::UnknownAuthNMethod { method: method })
        }
    } else {
        Err(SOCKS5Error::BadVersion { version: buf[0] })
    }
}

#[cfg(feature = "gssapi")]
/// Encapsulate `msg` with the GSSAPI context and write it to `stream`.
#[inline]
fn write_encapsulated<S>(
    stream: &mut S,
    ctx: Option<&mut ClientCtx>,
    msg: &[u8]
) -> Result<(), SOCKS5Error>
where
    S: Write {
    match ctx {
        Some(ctx) => {
            let msg = write_gssapi_payload(ctx, msg)?;

            stream
                .write_all(&msg)
                .map_err(|err| SOCKS5Error::IOError { error: err })
        }
        // We don't have a GSSAPI context, just send it.
        None => stream
            .write_all(msg)
            .map_err(|err| SOCKS5Error::IOError { error: err })
    }
}

#[cfg(not(feature = "gssapi"))]
/// Write `msg` to `stream`.
///
/// In the GSSAPI version, this performs GSSAPI encapsulation.
#[inline]
pub fn write_encapsulated<S>(
    stream: &mut S,
    msg: &[u8]
) -> Result<(), SOCKS5Error>
where
    S: Write {
    stream
        .write_all(msg)
        .map_err(|err| SOCKS5Error::IOError { error: err })
}

#[inline]
fn write_cmd_ipv4<S>(
    stream: &mut S,
    #[cfg(feature = "gssapi")] ctx: Option<&mut ClientCtx>,
    cmd: u8,
    addr: &Ipv4Addr,
    port: u16
) -> Result<(), SOCKS5Error>
where
    S: Write {
    #[cfg(feature = "log")]
    trace!(target: "socks5-protocol",
           "sending command {:x}, address {}",
           cmd, addr);

    let octets = addr.octets();
    let port_lo = (port & 0xff) as u8;
    let port_hi = (port >> 8) as u8;
    let buf = [
        VERSION, cmd, 0x00, IPV4, octets[0], octets[1], octets[2], octets[3],
        port_hi, port_lo
    ];

    write_encapsulated(
        stream,
        #[cfg(feature = "gssapi")]
        ctx,
        &buf
    )
}

#[inline]
fn write_cmd_ipv6<S>(
    stream: &mut S,
    #[cfg(feature = "gssapi")] ctx: Option<&mut ClientCtx>,
    cmd: u8,
    addr: &Ipv6Addr,
    port: u16
) -> Result<(), SOCKS5Error>
where
    S: Write {
    #[cfg(feature = "log")]
    trace!(target: "socks5-protocol",
           "sending command {:x}, address {}",
           cmd, addr);

    let octets = addr.octets();
    let port_lo = (port & 0xff) as u8;
    let port_hi = (port >> 8) as u8;
    let buf = [
        VERSION, cmd, 0x00, IPV6, octets[0], octets[1], octets[2], octets[3],
        octets[4], octets[5], octets[6], octets[7], octets[8], octets[9],
        octets[10], octets[11], octets[12], octets[13], octets[14], octets[15],
        port_hi, port_lo
    ];

    write_encapsulated(
        stream,
        #[cfg(feature = "gssapi")]
        ctx,
        &buf
    )
}

#[inline]
fn write_cmd_name<S>(
    stream: &mut S,
    #[cfg(feature = "gssapi")] ctx: Option<&mut ClientCtx>,
    cmd: u8,
    addr: &str,
    port: u16
) -> Result<(), SOCKS5Error>
where
    S: Write {
    #[cfg(feature = "log")]
    trace!(target: "socks5-protocol",
           "sending command {:x}, name \"{}\", port {}",
           cmd, addr, port);

    let nbytes = addr.len();

    if nbytes < 256 {
        let mut buf = Vec::with_capacity(4 + nbytes + 1 + 2);
        let port_lo = (port & 0xff) as u8;
        let port_hi = (port >> 8) as u8;

        buf.push(VERSION);
        buf.push(cmd);
        buf.push(0x00);
        buf.push(NAME);
        buf.push(nbytes as u8);
        buf.extend(addr.as_bytes());
        buf.push(port_hi);
        buf.push(port_lo);

        write_encapsulated(
            stream,
            #[cfg(feature = "gssapi")]
            ctx,
            &buf
        )
    } else {
        #[cfg(feature = "log")]
        error!(target: "socks5-protocol",
               "domain name length exceeds 256 characters");

        Err(SOCKS5Error::TooLong)
    }
}

#[inline]
fn write_cmd_ip<S>(
    stream: &mut S,
    #[cfg(feature = "gssapi")] ctx: Option<&mut ClientCtx>,
    cmd: u8,
    addr: &IpAddr,
    port: u16
) -> Result<(), SOCKS5Error>
where
    S: Write {
    match addr {
        IpAddr::V4(addr) => write_cmd_ipv4(
            stream,
            #[cfg(feature = "gssapi")]
            ctx,
            cmd,
            addr,
            port
        ),
        IpAddr::V6(addr) => write_cmd_ipv6(
            stream,
            #[cfg(feature = "gssapi")]
            ctx,
            cmd,
            addr,
            port
        )
    }
}

#[inline]
pub fn write_cmd<S>(
    stream: &mut S,
    #[cfg(feature = "gssapi")] ctx: Option<&mut ClientCtx>,
    cmd: u8,
    target: &IPEndpoint
) -> Result<(), SOCKS5Error>
where
    S: Write {
    match target.ip_endpoint() {
        IPEndpointAddr::Addr(addr) => write_cmd_ip(
            stream,
            #[cfg(feature = "gssapi")]
            ctx,
            cmd,
            addr,
            target.port()
        ),
        IPEndpointAddr::Name(name) => write_cmd_name(
            stream,
            #[cfg(feature = "gssapi")]
            ctx,
            cmd,
            name,
            target.port()
        )
    }
}

#[cfg(feature = "gssapi")]
#[inline]
pub fn parse_reply<S>(
    stream: &mut S,
    ctx: Option<&mut ClientCtx>
) -> Result<IPEndpoint, SOCKS5Error>
where
    S: Read {
    match ctx {
        Some(ctx) => {
            let buf = parse_gssapi_payload(stream, ctx)?;

            match (buf[0], buf[1]) {
                (VERSION, CMD_SUCCESS) => match (buf[2], buf[3]) {
                    (0x00, IPV4) => Ok(parse_ipv4_reply(&buf[4..])),
                    (0x00, NAME) if buf.len() != buf[4] as usize + 6 => {
                        let len = buf[4] as usize;
                        let port_hi = buf[len + 5] as u16;
                        let port_lo = buf[len + 6] as u16;
                        let port = port_hi << 8 | port_lo;
                        let buf = Vec::from(&buf[5..len + 5]);
                        let name = String::from_utf8(buf)
                            .map_err(|_| SOCKS5Error::BadDNSName)?;
                        let name = IPEndpointAddr::name(name);

                        Ok(IPEndpoint::new(name, port))
                    }
                    (0x00, NAME) => Err(SOCKS5Error::TooLong),
                    (0x00, IPV6) => Ok(parse_ipv6_reply(&buf[4..])),
                    (0x00, _) => Err(SOCKS5Error::BadAddrType { ty: buf[1] }),
                    (_, _) => Err(SOCKS5Error::BadReserved { reserved: buf[0] })
                },
                (VERSION, SERVER_ERROR) => Err(SOCKS5Error::ServerFailure),
                (VERSION, NOT_ALLOWED) => Err(SOCKS5Error::PermissionDenied),
                (VERSION, NETWORK_UNREACHABLE) => {
                    Err(SOCKS5Error::NetworkUnreachable)
                }
                (VERSION, HOST_UNREACHABLE) => {
                    Err(SOCKS5Error::HostUnreachable)
                }
                (VERSION, CONNECTION_REFUSED) => {
                    Err(SOCKS5Error::ConnectionRefused)
                }
                (VERSION, TTL_EXPIRED) => Err(SOCKS5Error::TTLExpired),
                (VERSION, CMD_NOT_SUPPORTED) => {
                    Err(SOCKS5Error::CmdNotSupported)
                }
                (VERSION, ADDR_NOT_SUPPORTED) => {
                    Err(SOCKS5Error::AddrTypeNotSupported)
                }
                (VERSION, _) => {
                    Err(SOCKS5Error::BadCmdReplyKind { kind: buf[0] })
                }
                (_, _) => Err(SOCKS5Error::BadVersion { version: buf[0] })
            }
        }
        None => parse_reply_no_ctx(stream)
    }
}

#[cfg(not(feature = "gssapi"))]
#[inline]
pub fn parse_reply<S>(stream: &mut S) -> Result<IPEndpoint, SOCKS5Error>
where
    S: Read {
    parse_reply_no_ctx(stream)
}

#[inline]
fn parse_ipv4_reply(buf: &[u8]) -> IPEndpoint {
    let ip = [buf[0], buf[1], buf[2], buf[3]];

    let ip = IPEndpointAddr::ip(IpAddr::from(ip));
    let port = (buf[4] as u16) << 8 | buf[5] as u16;
    let out = IPEndpoint::new(ip, port);

    #[cfg(feature = "log")]
    debug!(target: "socks5-protocol",
           "proxy replied with address {}",
           out);

    out
}

#[inline]
fn parse_ipv6_reply(buf: &[u8]) -> IPEndpoint {
    let ip = [
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
        buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]
    ];

    let ip = IPEndpointAddr::ip(IpAddr::from(ip));
    let port = (buf[16] as u16) << 8 | buf[17] as u16;
    let out = IPEndpoint::new(ip, port);

    #[cfg(feature = "log")]
    debug!(target: "socks5-protocol",
           "proxy replied with address {}",
           out);

    out
}

fn parse_reply_no_ctx<S>(stream: &mut S) -> Result<IPEndpoint, SOCKS5Error>
where
    S: Read {
    #[cfg(feature = "log")]
    trace!(target: "socks5-protocol",
           "parsing reply");

    // Read the first two bytes to see if there is an error.
    let mut buf = [0; 2];

    stream
        .read_exact(&mut buf[..])
        .map_err(|err| SOCKS5Error::IOError { error: err })?;

    match (buf[0], buf[1]) {
        (VERSION, CMD_SUCCESS) => {
            // Read the address type.
            stream
                .read_exact(&mut buf[..])
                .map_err(|err| SOCKS5Error::IOError { error: err })?;

            match (buf[0], buf[1]) {
                (0x00, IPV4) => {
                    // IPv4 address.
                    #[cfg(feature = "log")]
                    trace!(target: "socks5-protocol",
                           "parsing ipv4 address reply");

                    let mut buf = [0; 6];

                    stream
                        .read_exact(&mut buf[..])
                        .map_err(|err| SOCKS5Error::IOError { error: err })?;

                    Ok(parse_ipv4_reply(&buf[..]))
                }
                (0x00, NAME) => {
                    // Domain name address.
                    #[cfg(feature = "log")]
                    trace!(target: "socks5-protocol",
                           "parsing DNS name reply");

                    // Read the length
                    let mut buf = [0];

                    stream
                        .read_exact(&mut buf[..])
                        .map_err(|err| SOCKS5Error::IOError { error: err })?;

                    let len = buf[0] as usize;
                    let mut buf = vec![0; len + 2];

                    stream
                        .read_exact(&mut buf[..])
                        .map_err(|err| SOCKS5Error::IOError { error: err })?;

                    let port_lo = match buf.pop() {
                        Some(val) => Ok(val as u16),
                        None => {
                            // This should never happen.
                            #[cfg(feature = "log")]
                            error!(target: "socks5-protocol",
                                   "impossible case: reply buffer too short");

                            Err(Error::new(
                                ErrorKind::Other,
                                "internal protocol error"
                            ))
                        }
                    }
                    .map_err(|err| SOCKS5Error::IOError { error: err })?;
                    let port_hi = match buf.pop() {
                        Some(val) => Ok(val as u16),
                        None => {
                            // This should never happen.
                            #[cfg(feature = "log")]
                            error!(target: "socks5-protocol",
                                   "impossible case: reply buffer too short");

                            Err(Error::new(
                                ErrorKind::Other,
                                "internal protocol error"
                            ))
                        }
                    }
                    .map_err(|err| SOCKS5Error::IOError { error: err })?;
                    let port = port_hi << 8 | port_lo;
                    let name = String::from_utf8(buf)
                        .map_err(|_| SOCKS5Error::BadDNSName)?;
                    let name = IPEndpointAddr::name(name);
                    let out = IPEndpoint::new(name, port);

                    #[cfg(feature = "log")]
                    debug!(target: "socks5-protocol",
                           "proxy replied with address {}",
                           out);

                    Ok(out)
                }
                (0x00, IPV6) => {
                    // IPv6 address.
                    #[cfg(feature = "log")]
                    trace!(target: "socks5-protocol",
                           "parsing ipv6 address reply");

                    let mut buf = [0; 18];

                    stream
                        .read_exact(&mut buf[..])
                        .map_err(|err| SOCKS5Error::IOError { error: err })?;

                    Ok(parse_ipv6_reply(&buf[..]))
                }
                (0x00, _) => Err(SOCKS5Error::BadAddrType { ty: buf[1] }),
                (_, _) => Err(SOCKS5Error::BadReserved { reserved: buf[0] })
            }
        }
        (VERSION, SERVER_ERROR) => Err(SOCKS5Error::ServerFailure),
        (VERSION, NOT_ALLOWED) => Err(SOCKS5Error::PermissionDenied),
        (VERSION, NETWORK_UNREACHABLE) => Err(SOCKS5Error::NetworkUnreachable),
        (VERSION, HOST_UNREACHABLE) => Err(SOCKS5Error::HostUnreachable),
        (VERSION, CONNECTION_REFUSED) => Err(SOCKS5Error::ConnectionRefused),
        (VERSION, TTL_EXPIRED) => Err(SOCKS5Error::TTLExpired),
        (VERSION, CMD_NOT_SUPPORTED) => Err(SOCKS5Error::CmdNotSupported),
        (VERSION, ADDR_NOT_SUPPORTED) => Err(SOCKS5Error::AddrTypeNotSupported),
        (_, _) => Err(SOCKS5Error::BadVersion { version: buf[0] })
    }
}

#[inline]
pub fn write_password_authn<S>(
    stream: &mut S,
    name: &str,
    password: &str
) -> Result<(), SOCKS5Error>
where
    S: Write {
    let namelen = name.len();
    let passwordlen = password.len();

    if namelen < 256 && passwordlen < 256 {
        let mut buf = Vec::with_capacity(3 + namelen + passwordlen);

        buf.push(VERSION);
        buf.push(namelen as u8);
        buf.extend(name.as_bytes());
        buf.push(passwordlen as u8);
        buf.extend(password.as_bytes());

        stream
            .write_all(&buf)
            .map_err(|err| SOCKS5Error::IOError { error: err })
    } else if namelen >= 256 {
        #[cfg(feature = "log")]
        error!(target: "socks5-protocol",
               "username length exceeds 256 characters");

        Err(SOCKS5Error::TooLong)
    } else {
        #[cfg(feature = "log")]
        error!(target: "socks5-protocol",
               "password length exceeds 256 characters");

        Err(SOCKS5Error::TooLong)
    }
}

#[inline]
pub fn parse_password_authn_reply<S>(
    stream: &mut S
) -> Result<bool, SOCKS5Error>
where
    S: Read {
    #[cfg(feature = "log")]
    trace!(target: "socks5-protocol",
           "parsing authn method");

    let mut buf = [0; 2];

    stream
        .read_exact(&mut buf[..])
        .map_err(|err| SOCKS5Error::IOError { error: err })?;

    if buf[0] == 0x05 {
        // Zero indicates success.
        Ok(buf[1] == 0)
    } else {
        Err(SOCKS5Error::BadVersion { version: buf[0] })
    }
}

#[cfg(feature = "gssapi")]
#[inline]
pub fn prepare_gssapi(
    params: &SOCKS5GSSAPIParams
) -> Result<ClientCtx, SOCKS5Error> {
    // Prepare the mechanisms.
    let mut mechs =
        OidSet::new().map_err(|err| SOCKS5Error::GSSAPIError { error: err })?;

    mechs
        .add(&GSS_MECH_KRB5)
        .map_err(|err| SOCKS5Error::GSSAPIError { error: err })?;

    // Prepare the principal name.
    let cred = match params.name() {
        // A principal name was provided.
        Some(name) => {
            let name =
                Name::new(name.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
                    .map_err(|err| SOCKS5Error::GSSAPIError { error: err })?;
            let name = name
                .canonicalize(Some(&GSS_MECH_KRB5))
                .map_err(|err| SOCKS5Error::GSSAPIError { error: err })?;

            Cred::acquire(
                Some(&name),
                params.time_req(),
                CredUsage::Initiate,
                Some(&mechs)
            )
            .map_err(|err| SOCKS5Error::GSSAPIError { error: err })?
        }
        // No principal name was provided.
        None => Cred::acquire(
            None,
            params.time_req(),
            CredUsage::Initiate,
            Some(&mechs)
        )
        .map_err(|err| SOCKS5Error::GSSAPIError { error: err })?
    };

    // Prepare the service name.
    let service =
        Name::new(params.service().as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
            .map_err(|err| SOCKS5Error::GSSAPIError { error: err })?;
    let service = service
        .canonicalize(Some(&GSS_MECH_KRB5))
        .map_err(|err| SOCKS5Error::GSSAPIError { error: err })?;

    Ok(ClientCtx::new(
        cred,
        service,
        CtxFlags::GSS_C_MUTUAL_FLAG,
        Some(&GSS_MECH_KRB5)
    ))
}

#[cfg(feature = "gssapi")]
#[inline]
pub fn write_gssapi_step<W>(
    stream: &mut W,
    msg: &Buf
) -> Result<(), SOCKS5Error>
where
    W: Write {
    let len = msg.len();
    let mut buf = Vec::with_capacity(len + 4);
    let len = len as u16;

    buf.push(GSSAPI_VERSION);
    buf.push(GSSAPI_CTX_NEGOTIATE);
    buf.push((len >> 8) as u8);
    buf.push((len & 0xff) as u8);
    buf.extend(msg.as_ref());

    stream
        .write_all(&buf)
        .map_err(|err| SOCKS5Error::IOError { error: err })
}

#[cfg(feature = "gssapi")]
#[inline]
pub fn parse_gssapi_step<R>(stream: &mut R) -> Result<Vec<u8>, SOCKS5Error>
where
    R: Read {
    // Read the first two bytes to determine whether there is more.
    let mut buf = [0; 2];

    stream
        .read_exact(&mut buf[..])
        .map_err(|err| SOCKS5Error::IOError { error: err })?;

    // Check the version and status.
    match (buf[0], buf[1]) {
        // Read in the token and return it.
        (GSSAPI_VERSION, GSSAPI_CTX_NEGOTIATE) => {
            let mut buf = [0; 2];

            stream
                .read_exact(&mut buf[..])
                .map_err(|err| SOCKS5Error::IOError { error: err })?;

            let len = ((buf[0] as usize) << 8) | (buf[1] as usize);
            let mut buf = vec![0; len];

            stream
                .read_exact(&mut buf[..])
                .map_err(|err| SOCKS5Error::IOError { error: err })?;

            Ok(buf)
        }
        // Server rejected the authentication attempt.
        (GSSAPI_VERSION, GSSAPI_CTX_NEGOTIATE_ERROR) => {
            #[cfg(feature = "log")]
            warn!(target: "socks5-protocol",
                  "server refused GSSAPI authentication");

            Err(SOCKS5Error::AuthNFailed)
        }
        // Bad reply type.
        (GSSAPI_VERSION, _) => {
            #[cfg(feature = "log")]
            info!(target: "socks5-protocol",
                  "bad GSSAPI reply type ({})",
                  buf[1]);

            Err(SOCKS5Error::BadGSSAPIReplyKind { kind: buf[1] })
        }
        // Bad version.
        (_, _) => Err(SOCKS5Error::BadVersion { version: buf[0] })
    }
}

#[cfg(feature = "gssapi")]
#[inline]
pub fn write_gssapi_seclvl<W>(
    stream: &mut W,
    ctx: &mut ClientCtx,
    seclvl: u8
) -> Result<(), SOCKS5Error>
where
    W: Write {
    let msg = ctx
        .wrap(true, &[seclvl])
        .map_err(|err| SOCKS5Error::GSSAPIError { error: err })?;
    let len = msg.len();
    let mut buf = Vec::with_capacity(len + 4);
    let len = len as u16;

    buf.push(GSSAPI_VERSION);
    buf.push(GSSAPI_SECLVL_NEGOTIATE);
    buf.push((len >> 8) as u8);
    buf.push((len & 0xff) as u8);
    buf.extend(msg.as_ref());

    stream
        .write_all(&buf)
        .map_err(|err| SOCKS5Error::IOError { error: err })
}

#[cfg(feature = "gssapi")]
#[inline]
pub fn parse_gssapi_seclvl<R>(
    stream: &mut R,
    ctx: &mut ClientCtx
) -> Result<u8, SOCKS5Error>
where
    R: Read {
    // Read the first two bytes to determine whether there is more.
    let mut buf = [0; 2];

    stream
        .read_exact(&mut buf[..])
        .map_err(|err| SOCKS5Error::IOError { error: err })?;

    // Check the version and status.
    match (buf[0], buf[1]) {
        // Unwrap the message and extract the security level.
        (GSSAPI_VERSION, GSSAPI_SECLVL_NEGOTIATE) => {
            let mut buf = [0; 2];

            stream
                .read_exact(&mut buf[..])
                .map_err(|err| SOCKS5Error::IOError { error: err })?;

            let len = ((buf[0] as usize) << 8) | (buf[1] as usize);
            let mut buf = vec![0; len];

            stream
                .read_exact(&mut buf[..])
                .map_err(|err| SOCKS5Error::IOError { error: err })?;

            let buf = ctx
                .unwrap(&buf)
                .map_err(|err| SOCKS5Error::GSSAPIError { error: err })?;

            Ok(buf[0])
        }
        // Bad reply type.
        (GSSAPI_VERSION, _) => {
            #[cfg(feature = "log")]
            info!(target: "socks5-protocol",
                  "bad GSSAPI reply type ({})",
                  buf[1]);

            Err(SOCKS5Error::BadGSSAPIReplyKind { kind: buf[1] })
        }
        // Bad version.
        (_, _) => Err(SOCKS5Error::BadVersion { version: buf[0] })
    }
}

#[cfg(feature = "gssapi")]
#[inline]
pub fn write_gssapi_payload(
    ctx: &mut ClientCtx,
    msg: &[u8]
) -> Result<Vec<u8>, SOCKS5WrapError> {
    let msg = ctx
        .wrap(true, msg)
        .map_err(|err| SOCKS5WrapError::GSSAPIError { error: err })?;
    let len = msg.len();
    let mut buf = Vec::with_capacity(len + 4);
    let len = len as u16;

    buf.push(GSSAPI_VERSION);
    buf.push(GSSAPI_PAYLOAD);
    buf.push((len >> 8) as u8);
    buf.push((len & 0xff) as u8);
    buf.extend(msg.as_ref());

    Ok(buf)
}

#[cfg(feature = "gssapi")]
pub fn parse_gssapi_payload<R>(
    stream: &mut R,
    ctx: &mut ClientCtx
) -> Result<Buf, SOCKS5Error>
where
    R: Read {
    // Read the first two bytes to determine whether there is more.
    let mut buf = [0; 2];

    stream
        .read_exact(&mut buf[..])
        .map_err(|err| SOCKS5Error::IOError { error: err })?;

    // Check the version and status.
    match (buf[0], buf[1]) {
        // Unwrap the payload.
        (GSSAPI_VERSION, GSSAPI_PAYLOAD) => {
            let mut buf = [0; 2];

            stream
                .read_exact(&mut buf[..])
                .map_err(|err| SOCKS5Error::IOError { error: err })?;

            let len = ((buf[0] as usize) << 8) | (buf[1] as usize);
            let mut buf = vec![0; len];

            stream
                .read_exact(&mut buf[..])
                .map_err(|err| SOCKS5Error::IOError { error: err })?;

            let buf = ctx
                .unwrap(&buf)
                .map_err(|err| SOCKS5Error::GSSAPIError { error: err })?;

            Ok(buf)
        }
        // Bad reply type.
        (GSSAPI_VERSION, _) => {
            Err(SOCKS5Error::BadGSSAPIReplyKind { kind: buf[1] })
        }
        // Bad version.
        (_, _) => Err(SOCKS5Error::BadVersion { version: buf[0] })
    }
}

#[cfg(feature = "gssapi")]
pub fn unwrap_gssapi_payload(
    msg: &mut [u8],
    ctx: &mut Arc<Mutex<ClientCtx>>
) -> Result<Buf, SOCKS5WrapError> {
    if msg.len() >= 4 {
        let len = match (msg[0], msg[1]) {
            // Unwrap the payload.
            (GSSAPI_VERSION, GSSAPI_PAYLOAD) => {
                Ok(((msg[2] as usize) << 8) | (msg[3] as usize))
            }
            // Bad reply type.
            (GSSAPI_VERSION, _) => {
                Err(SOCKS5WrapError::BadGSSAPIReplyKind { kind: msg[1] })
            }
            // Bad version.
            (_, _) => Err(SOCKS5WrapError::BadVersion { version: msg[0] })
        }?;

        if msg.len() >= len + 4 {
            let buf = match ctx.lock() {
                Ok(mut ctx) => ctx
                    .unwrap(&msg[4..len + 4])
                    .map_err(|err| SOCKS5WrapError::GSSAPIError { error: err }),
                Err(_) => Err(SOCKS5WrapError::MutexPoison)
            }?;

            Ok(buf)
        } else {
            Err(SOCKS5WrapError::TooShort)
        }
    } else {
        Err(SOCKS5WrapError::TooShort)
    }
}

#[inline]
pub fn prepare_udp_payload(
    endpoint: &IPEndpoint,
    data: &[u8]
) -> Result<Vec<u8>, SOCKS5WrapError> {
    let port = endpoint.port();

    match endpoint.ip_endpoint() {
        IPEndpointAddr::Addr(IpAddr::V4(addr)) => {
            let mut buf = Vec::with_capacity(data.len() + 10);

            buf.push(0);
            buf.push(0);
            buf.push(0);
            buf.push(IPV4);
            buf.extend(addr.octets());
            buf.push((port >> 8) as u8);
            buf.push((port & 0xff) as u8);
            buf.extend(data);

            Ok(buf)
        }
        IPEndpointAddr::Addr(IpAddr::V6(addr)) => {
            let mut buf = Vec::with_capacity(data.len() + 22);

            buf.push(0);
            buf.push(0);
            buf.push(0);
            buf.push(IPV6);
            buf.extend(addr.octets());
            buf.push((port >> 8) as u8);
            buf.push((port & 0xff) as u8);
            buf.extend(data);

            Ok(buf)
        }
        IPEndpointAddr::Name(name) if name.len() < 256 => {
            let mut buf = Vec::with_capacity(name.len() + data.len() + 6);

            buf.push(0);
            buf.push(0);
            buf.push(0);
            buf.push(NAME);
            buf.push(name.len() as u8);
            buf.extend(name.as_bytes());
            buf.push((port >> 8) as u8);
            buf.push((port & 0xff) as u8);
            buf.extend(data);

            Ok(buf)
        }
        IPEndpointAddr::Name(_) => Err(SOCKS5WrapError::NameTooLong)
    }
}

#[inline]
pub fn parse_udp_header(
    msg: &[u8]
) -> Result<(usize, IPEndpoint), SOCKS5WrapError> {
    if msg.len() >= 6 {
        match (msg[0], msg[1]) {
            (0, 0) => match msg[2] {
                0 => match msg[3] {
                    IPV4 => {
                        if msg.len() >= 10 {
                            let ip = [msg[4], msg[5], msg[6], msg[7]];
                            let ip = IPEndpointAddr::ip(IpAddr::from(ip));
                            let port = (msg[8] as u16) << 8 | msg[9] as u16;

                            Ok((10, IPEndpoint::new(ip, port)))
                        } else {
                            Err(SOCKS5WrapError::TooShort)
                        }
                    }
                    IPV6 => {
                        if msg.len() >= 22 {
                            let ip = [
                                msg[4], msg[5], msg[6], msg[7], msg[8], msg[9],
                                msg[10], msg[11], msg[12], msg[13], msg[14],
                                msg[15], msg[16], msg[17], msg[18], msg[19]
                            ];
                            let ip = IPEndpointAddr::ip(IpAddr::from(ip));
                            let port = (msg[20] as u16) << 8 | msg[21] as u16;

                            Ok((22, IPEndpoint::new(ip, port)))
                        } else {
                            Err(SOCKS5WrapError::TooShort)
                        }
                    }
                    NAME => {
                        let namelen = msg[4] as usize;
                        let port = (msg[namelen + 5] as u16) << 8 |
                            msg[namelen + 6] as u16;

                        if msg.len() >= 7 + namelen {
                            let namebuf = &msg[5..namelen + 5];
                            let name = String::from_utf8(namebuf.to_vec())
                                .map_err(|_| SOCKS5WrapError::BadDNSName)?;
                            let name = IPEndpointAddr::name(name);

                            Ok((7 + namelen, IPEndpoint::new(name, port)))
                        } else {
                            Err(SOCKS5WrapError::TooShort)
                        }
                    }
                    ty => Err(SOCKS5WrapError::BadAddrType { ty: ty })
                },
                _ => Err(SOCKS5WrapError::FragNotSupported)
            },
            (0, hi) => Err(SOCKS5WrapError::BadReserved { reserved: hi }),
            (lo, _) => Err(SOCKS5WrapError::BadReserved { reserved: lo })
        }
    } else {
        Err(SOCKS5WrapError::TooShort)
    }
}

#[cfg(test)]
use std::collections::VecDeque;

#[cfg(not(feature = "gssapi"))]
#[test]
fn test_write_authn_methods_no_password() {
    let mut buf = VecDeque::with_capacity(3);
    let expected = [0x05, 0x01, 0x00];

    write_authn_methods(&mut buf, false).expect("Expected success");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(not(feature = "gssapi"))]
#[test]
fn test_write_authn_methods_password() {
    let mut buf = VecDeque::with_capacity(4);
    let expected = [0x05, 0x02, 0x00, 0x02];

    write_authn_methods(&mut buf, true).expect("Expected success");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(feature = "gssapi")]
#[test]
fn test_write_authn_methods_no_password_no_gssapi() {
    let mut buf = VecDeque::with_capacity(3);
    let expected = [0x05, 0x01, 0x00];

    write_authn_methods(&mut buf, false, false).expect("Expected success");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(feature = "gssapi")]
#[test]
fn test_write_authn_methods_password_no_gssapi() {
    let mut buf = VecDeque::with_capacity(4);
    let expected = [0x05, 0x02, 0x00, 0x02];

    write_authn_methods(&mut buf, false, true).expect("Expected success");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(feature = "gssapi")]
#[test]
fn test_write_authn_methods_no_password_gssapi() {
    let mut buf = VecDeque::with_capacity(4);
    let expected = [0x05, 0x02, 0x00, 0x01];

    write_authn_methods(&mut buf, true, false).expect("Expected success");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(feature = "gssapi")]
#[test]
fn test_write_authn_methods_password_gssapi() {
    let mut buf = VecDeque::with_capacity(5);
    let expected = [0x05, 0x03, 0x00, 0x01, 0x02];

    write_authn_methods(&mut buf, true, true).expect("Expected success");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[test]
fn test_parse_method_no_method() {
    let msg = [0x05, 0x00];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_method(&mut buf).expect("Expected success");

    assert_eq!(res, AuthNMech::None);
}

#[cfg(feature = "gssapi")]
#[test]
fn test_parse_method_gssapi() {
    let msg = [0x05, 0x01];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_method(&mut buf).expect("Expected success");

    assert_eq!(res, AuthNMech::GSSAPI);
}

#[test]
fn test_parse_method_password() {
    let msg = [0x05, 0x02];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_method(&mut buf).expect("Expected success");

    assert_eq!(res, AuthNMech::Password);
}

#[test]
fn test_write_password_authn() {
    let mut buf = VecDeque::with_capacity(11);
    let expected = [
        0x05, 0x04, 0x75, 0x73, 0x65, 0x72, 0x04, 0x70, 0x61, 0x73, 0x73
    ];

    write_password_authn(&mut buf, "user", "pass").expect("Expected success");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[test]
fn test_parse_password_authn_reply_success() {
    let msg = [0x05, 0x00];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_password_authn_reply(&mut buf).expect("Expected success");

    assert!(res);
}

#[test]
fn test_parse_password_authn_reply_fail() {
    let msg = [0x05, 0x01];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_password_authn_reply(&mut buf).expect("Expected success");

    assert!(!res);
}

#[cfg(not(feature = "gssapi"))]
#[test]
fn test_write_cmd_connect_ipv4() {
    let mut buf = VecDeque::with_capacity(10);
    let ip = IPEndpointAddr::ip(IpAddr::from([0x01, 0x02, 0x03, 0x04]));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let expected = [0x05, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37];

    write_cmd(&mut buf, 0x01, &endpoint).expect("Expected some");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(feature = "gssapi")]
#[test]
fn test_write_cmd_connect_ipv4() {
    let mut buf = VecDeque::with_capacity(10);
    let ip = IPEndpointAddr::ip(IpAddr::from([0x01, 0x02, 0x03, 0x04]));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let expected = [0x05, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37];

    write_cmd(&mut buf, None, 0x01, &endpoint).expect("Expected some");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(not(feature = "gssapi"))]
#[test]
fn test_write_cmd_connect_name() {
    let mut buf = VecDeque::with_capacity(11);
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    write_cmd(&mut buf, 0x01, &endpoint).expect("Expected some");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(feature = "gssapi")]
#[test]
fn test_write_cmd_connect_name() {
    let mut buf = VecDeque::with_capacity(11);
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let expected = [
        0x05, 0x01, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];

    write_cmd(&mut buf, None, 0x01, &endpoint).expect("Expected some");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(not(feature = "gssapi"))]
#[test]
fn test_write_cmd_connect_ipv6() {
    let mut buf = VecDeque::with_capacity(22);
    let ip = IPEndpointAddr::ip(IpAddr::from([
        0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34
    ]));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let expected = [
        0x05, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14,
        0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x13, 0x37
    ];

    write_cmd(&mut buf, 0x01, &endpoint).expect("Expected some");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(feature = "gssapi")]
#[test]
fn test_write_cmd_connect_ipv6() {
    let mut buf = VecDeque::with_capacity(22);
    let ip = IPEndpointAddr::ip(IpAddr::from([
        0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34
    ]));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let expected = [
        0x05, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14,
        0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x13, 0x37
    ];

    write_cmd(&mut buf, None, 0x01, &endpoint).expect("Expected some");

    assert_eq!(buf.make_contiguous(), &expected);
}

#[cfg(feature = "gssapi")]
#[test]
fn test_parse_reply_ipv4() {
    let msg = [0x05, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_reply(&mut buf, None).expect("Expected success");
    let ip = IPEndpointAddr::ip(IpAddr::from([0x01, 0x02, 0x03, 0x04]));
    let port = 0x1337;

    assert_eq!(res, IPEndpoint::new(ip, port));
}

#[cfg(feature = "gssapi")]
#[test]
fn test_parse_reply_name() {
    let msg = [
        0x05, 0x00, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_reply(&mut buf, None).expect("Expected success");
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;

    assert_eq!(res, IPEndpoint::new(ip, port));
}

#[cfg(feature = "gssapi")]
#[test]
fn test_parse_reply_ipv6() {
    let msg = [
        0x05, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14,
        0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x13, 0x37
    ];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_reply(&mut buf, None).expect("Expected success");
    let ip = IPEndpointAddr::ip(IpAddr::from([
        0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34
    ]));
    let port = 0x1337;

    assert_eq!(res, IPEndpoint::new(ip, port));
}

#[cfg(not(feature = "gssapi"))]
#[test]
fn test_parse_reply_ipv4() {
    let msg = [0x05, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_reply(&mut buf).expect("Expected success");
    let ip = IPEndpointAddr::ip(IpAddr::from([0x01, 0x02, 0x03, 0x04]));
    let port = 0x1337;

    assert_eq!(res, IPEndpoint::new(ip, port));
}

#[cfg(not(feature = "gssapi"))]
#[test]
fn test_parse_reply_name() {
    let msg = [
        0x05, 0x00, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37
    ];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_reply(&mut buf).expect("Expected success");
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;

    assert_eq!(res, IPEndpoint::new(ip, port));
}

#[cfg(not(feature = "gssapi"))]
#[test]
fn test_parse_reply_ipv6() {
    let msg = [
        0x05, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14,
        0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x13, 0x37
    ];
    let mut buf = VecDeque::from(msg.to_vec());
    let res = parse_reply(&mut buf).expect("Expected success");
    let ip = IPEndpointAddr::ip(IpAddr::from([
        0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34
    ]));
    let port = 0x1337;

    assert_eq!(res, IPEndpoint::new(ip, port));
}

#[test]
fn test_prepare_udp_ipv4() {
    let ip = IPEndpointAddr::ip(IpAddr::from([0x01, 0x02, 0x03, 0x04]));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let data = [0xde, 0xad, 0xc0, 0xde];
    let expected = [
        0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37, 0xde, 0xad,
        0xc0, 0xde
    ];
    let payload = prepare_udp_payload(&endpoint, &data).expect("Expected some");

    assert_eq!(&payload, &expected);
}

#[test]
fn test_prepare_udp_name() {
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let data = [0xde, 0xad, 0xc0, 0xde];
    let expected = [
        0x00, 0x00, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37, 0xde,
        0xad, 0xc0, 0xde
    ];
    let payload = prepare_udp_payload(&endpoint, &data).expect("Expected some");

    assert_eq!(&payload, &expected);
}

#[test]
fn test_prepare_udp_ipv6() {
    let ip = IPEndpointAddr::ip(IpAddr::from([
        0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34
    ]));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let data = [0xde, 0xad, 0xc0, 0xde];
    let expected = [
        0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14,
        0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x13, 0x37, 0xde, 0xad,
        0xc0, 0xde
    ];
    let payload = prepare_udp_payload(&endpoint, &data).expect("Expected some");

    assert_eq!(&payload, &expected);
}

#[test]
fn test_parse_udp_header_ipv4() {
    let msg = [
        0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37, 0xde, 0xad,
        0xc0, 0xde
    ];
    let (nbytes, endpoint) = parse_udp_header(&msg).expect("Expected success");
    let ip = IPEndpointAddr::ip(IpAddr::from([0x01, 0x02, 0x03, 0x04]));
    let port = 0x1337;

    assert_eq!(endpoint, IPEndpoint::new(ip, port));
    assert_eq!(nbytes, 10);
}

#[test]
fn test_parse_udp_header_name() {
    let msg = [
        0x00, 0x00, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37, 0xde,
        0xad, 0xc0, 0xde
    ];
    let (nbytes, endpoint) = parse_udp_header(&msg).expect("Expected success");
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;

    assert_eq!(endpoint, IPEndpoint::new(ip, port));
    assert_eq!(nbytes, 11);
}

#[test]
fn test_parse_udp_header_ipv6() {
    let msg = [
        0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14,
        0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x13, 0x37, 0xde, 0xad,
        0xc0, 0xde
    ];
    let (nbytes, endpoint) = parse_udp_header(&msg).expect("Expected success");
    let ip = IPEndpointAddr::ip(IpAddr::from([
        0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34
    ]));
    let port = 0x1337;

    assert_eq!(endpoint, IPEndpoint::new(ip, port));
    assert_eq!(nbytes, 22);
}
