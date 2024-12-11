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

//! Communications over an established SOCKS5 connection.
//!
//! This module contains utilities for communicating over a SOCKS5
//! connection after it has been established, both in TCP and UDP modes.
use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
#[cfg(feature = "gssapi")]
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
#[cfg(feature = "gssapi")]
use std::sync::Arc;
#[cfg(feature = "gssapi")]
use std::sync::Mutex;

use constellation_auth::cred::Credentials;
use constellation_auth::cred::CredentialsMut;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreateParam;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
#[cfg(feature = "gssapi")]
use libgssapi::context::ClientCtx;

#[cfg(feature = "gssapi")]
use crate::error::SOCKS5Error;
use crate::error::SOCKS5UDPError;
#[cfg(feature = "gssapi")]
use crate::error::SOCKS5WrapError;
use crate::proto;

/// [DatagramXfrm] instance for encapsulating UDP packets.
///
/// This contains all information needed to encapsulate UDP packets
/// for a SOCKS5 UDP association.  The [wrap](DatagramXfrm::wrap)
/// and [unwrap](DatagramXfrm::unwrap) functions will handle all
/// RFC 1928 headers, as well as GSSAPI encapsulation if applicable.
pub enum SOCKS5UDPXfrm<Inner>
where
    Inner: DatagramXfrm {
    #[cfg(feature = "gssapi")]
    GSSAPI {
        ctx: Arc<Mutex<ClientCtx>>,
        proxy: Inner::PeerAddr,
        inner: Inner
    },
    Basic {
        proxy: Inner::PeerAddr,
        inner: Inner
    }
}

/// SOCKS5 TCP stream.
///
/// This holds the established SOCKS5 stream, as well as the GSSAPI
/// context, if applicable.  The [Read] and [Write] instances will
/// handle GSSAPI encapsulation if necessary.
#[derive(Debug)]
pub enum SOCKS5Stream<Stream: Read + Write> {
    #[cfg(feature = "gssapi")]
    /// GSSAPI-secured stream.
    GSSAPI {
        /// GSSAPI context.
        ctx: ClientCtx,
        /// The raw connected stream.
        stream: Stream
    },
    /// Passthrough stream, no GSSAPI.
    Passthru {
        /// The connected stream.
        stream: Stream
    }
}

/// Type of creation parameters for [SOCKS5UDPXfrm].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SOCKS5Param<Param, PeerAddr> {
    /// Datagram socket address.
    datagram: Param,
    /// Proxy address.
    proxy: PeerAddr
}

impl<Inner> DatagramXfrmCreateParam for SOCKS5UDPXfrm<Inner>
where
    Inner: DatagramXfrmCreateParam
{
    type Param = SOCKS5Param<Inner::Param, Inner::PeerAddr>;
    type ParamError = Inner::ParamError;
    type Socket = Inner::Socket;

    fn param(
        &self,
        socket: &Self::Socket
    ) -> Result<Self::Param, Self::ParamError> {
        let (proxy, inner) = match self {
            #[cfg(feature = "gssapi")]
            SOCKS5UDPXfrm::GSSAPI { proxy, inner, .. } => (proxy, inner),
            SOCKS5UDPXfrm::Basic { proxy, inner } => (proxy, inner)
        };
        let datagram = inner.param(socket)?;

        Ok(SOCKS5Param {
            datagram: datagram,
            proxy: proxy.clone()
        })
    }
}

impl<Param, PeerAddr> SOCKS5Param<Param, PeerAddr> {
    /// Create a `SOCKS5Param` from its components.
    #[inline]
    pub fn new(
        datagram: Param,
        proxy: PeerAddr
    ) -> Self {
        SOCKS5Param {
            datagram: datagram,
            proxy: proxy
        }
    }

    /// Get the parameter for the connection to the proxy.
    #[inline]
    pub fn inner(&self) -> &Param {
        &self.datagram
    }

    /// Get the address of the proxy to which to send traffic.
    #[inline]
    pub fn proxy_addr(&self) -> &PeerAddr {
        &self.proxy
    }

    /// Decompose this into its components.
    #[inline]
    pub fn take(self) -> (Param, PeerAddr) {
        (self.datagram, self.proxy)
    }
}

impl<Inner> Credentials for SOCKS5Stream<Inner>
where
    Inner: Read + Write
{
    type Cred<'a> = Infallible
    where Self: 'a;
    type CredError = Infallible;

    #[inline]
    fn creds(&self) -> Result<Option<Self::Cred<'_>>, Self::CredError> {
        Ok(None)
    }
}

impl<Inner> CredentialsMut for SOCKS5Stream<Inner>
where
    Inner: Read + Write
{
    type Cred<'a> = Infallible
    where Self: 'a;
    type CredError = Infallible;

    #[inline]
    fn creds(&mut self) -> Result<Option<Self::Cred<'_>>, Self::CredError> {
        <Self as Credentials>::creds(self)
    }
}

impl<Inner> SOCKS5UDPXfrm<Inner>
where
    Inner: DatagramXfrm
{
    #[cfg(feature = "gssapi")]
    #[inline]
    pub fn create(
        proxy: Inner::PeerAddr,
        inner: Inner,
        ctx: Option<Arc<Mutex<ClientCtx>>>
    ) -> Self {
        match ctx {
            Some(ctx) => SOCKS5UDPXfrm::GSSAPI {
                proxy: proxy,
                ctx: ctx,
                inner: inner
            },
            None => SOCKS5UDPXfrm::Basic {
                proxy: proxy,
                inner: inner
            }
        }
    }

    #[cfg(not(feature = "gssapi"))]
    #[inline]
    pub fn create(
        proxy: Inner::PeerAddr,
        inner: Inner
    ) -> Self {
        SOCKS5UDPXfrm::Basic {
            proxy: proxy,
            inner: inner
        }
    }
}

impl<Stream> Read for SOCKS5Stream<Stream>
where
    Stream: Read + Write
{
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match self {
            #[cfg(feature = "gssapi")]
            SOCKS5Stream::GSSAPI { ctx, stream } => {
                let msg = proto::parse_gssapi_payload(stream, ctx).map_err(
                    |err| match err {
                        SOCKS5Error::IOError { error } => error,
                        err => Error::new(ErrorKind::Other, err.to_string())
                    }
                )?;
                let len = msg.len();

                buf.clone_from_slice(msg.as_ref());

                Ok(len)
            }
            SOCKS5Stream::Passthru { stream } => stream.read(buf)
        }
    }
}

impl<Stream> Write for SOCKS5Stream<Stream>
where
    Stream: Read + Write
{
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self {
            #[cfg(feature = "gssapi")]
            SOCKS5Stream::GSSAPI { ctx, stream } => {
                let msg =
                    proto::write_gssapi_payload(ctx, buf).map_err(|err| {
                        Error::new(ErrorKind::Other, err.to_string())
                    })?;

                stream.write_all(&msg)?;

                Ok(buf.len())
            }
            SOCKS5Stream::Passthru { stream } => stream.write(buf)
        }
    }

    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), Error> {
        match self {
            #[cfg(feature = "gssapi")]
            SOCKS5Stream::GSSAPI { ctx, stream } => {
                let msg =
                    proto::write_gssapi_payload(ctx, buf).map_err(|err| {
                        Error::new(ErrorKind::Other, err.to_string())
                    })?;

                stream.write_all(&msg)
            }
            SOCKS5Stream::Passthru { stream } => stream.write_all(buf)
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "gssapi")]
            SOCKS5Stream::GSSAPI { stream, .. } => stream.flush(),
            SOCKS5Stream::Passthru { stream } => stream.flush()
        }
    }
}

impl<Inner> DatagramXfrm for SOCKS5UDPXfrm<Inner>
where
    Inner: DatagramXfrm
{
    type Error = SOCKS5UDPError<Inner::Error>;
    type LocalAddr = Inner::LocalAddr;
    type PeerAddr = IPEndpoint;
    type SizeError = Inner::SizeError;

    #[inline]
    fn header_size(
        &self,
        addr: &IPEndpoint
    ) -> Result<usize, Inner::SizeError> {
        let header = match addr.ip_endpoint() {
            IPEndpointAddr::Addr(IpAddr::V4(_)) => 10,
            IPEndpointAddr::Addr(IpAddr::V6(_)) => 22,
            IPEndpointAddr::Name(name) => 7 + name.len()
        };
        let inner = match self {
            #[cfg(feature = "gssapi")]
            SOCKS5UDPXfrm::GSSAPI { inner, proxy, .. } => {
                inner.header_size(proxy)?
            }
            SOCKS5UDPXfrm::Basic { inner, proxy } => inner.header_size(proxy)?
        };

        Ok(header + inner)
    }

    fn wrap(
        &mut self,
        msg: &[u8],
        addr: IPEndpoint
    ) -> Result<(Option<Vec<u8>>, Self::LocalAddr), Self::Error> {
        match self {
            #[cfg(feature = "gssapi")]
            SOCKS5UDPXfrm::GSSAPI { inner, proxy, ctx } => {
                let msg = proto::prepare_udp_payload(&addr, msg)
                    .map_err(|err| SOCKS5UDPError::Wrap { error: err })?;
                let msg = match ctx.lock() {
                    Ok(mut ctx) => proto::write_gssapi_payload(&mut ctx, &msg),
                    Err(_) => Err(SOCKS5WrapError::MutexPoison)
                }
                .map_err(|err| SOCKS5UDPError::Wrap { error: err })?;

                let (wrapped, addr) = inner
                    .wrap(&msg, proxy.clone())
                    .map_err(|e| SOCKS5UDPError::Inner { inner: e })?;

                match wrapped {
                    Some(msg) => Ok((Some(msg), addr)),
                    None => Ok((Some(msg), addr))
                }
            }
            SOCKS5UDPXfrm::Basic { inner, proxy } => {
                let msg = proto::prepare_udp_payload(&addr, msg)
                    .map_err(|err| SOCKS5UDPError::Wrap { error: err })?;
                let (wrapped, addr) = inner
                    .wrap(&msg, proxy.clone())
                    .map_err(|e| SOCKS5UDPError::Inner { inner: e })?;

                match wrapped {
                    Some(msg) => Ok((Some(msg), addr)),
                    None => Ok((Some(msg), addr))
                }
            }
        }
    }

    /// Unwrap the message in `buf` in-place.
    fn unwrap(
        &mut self,
        buf: &mut [u8],
        addr: Self::LocalAddr
    ) -> Result<(usize, Self::PeerAddr), Self::Error> {
        match self {
            #[cfg(feature = "gssapi")]
            SOCKS5UDPXfrm::GSSAPI { ctx, inner, .. } => {
                let (size, _) = inner
                    .unwrap(buf, addr)
                    .map_err(|err| SOCKS5UDPError::Inner { inner: err })?;
                let msg = proto::unwrap_gssapi_payload(&mut buf[..size], ctx)
                    .map_err(|err| SOCKS5UDPError::Wrap { error: err })?;
                let (offset, endpoint) = proto::parse_udp_header(&buf[..size])
                    .map_err(|err| SOCKS5UDPError::Wrap { error: err })?;

                buf[..msg.len()].copy_from_slice(&msg);

                Ok((size - offset, endpoint))
            }
            SOCKS5UDPXfrm::Basic { inner, .. } => {
                let (size, _) = inner
                    .unwrap(buf, addr)
                    .map_err(|err| SOCKS5UDPError::Inner { inner: err })?;
                let (offset, endpoint) = proto::parse_udp_header(&buf[..size])
                    .map_err(|err| SOCKS5UDPError::Wrap { error: err })?;

                buf.copy_within(offset..size, 0);

                Ok((size - offset, endpoint))
            }
        }
    }
}

impl<Proxy, PeerAddr> Display for SOCKS5Param<Proxy, PeerAddr>
where
    Proxy: Display,
    PeerAddr: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        write!(f, "{} (via {})", self.proxy, self.datagram)
    }
}

#[cfg(test)]
use constellation_common::net::PassthruDatagramXfrm;

#[test]
fn test_udp_xfrm_wrap_ipv4() {
    let local_addr = IpAddr::from([0xf1, 0xf2, 0xf3, 0xf4]);
    let mut xfrm = SOCKS5UDPXfrm::Basic {
        inner: PassthruDatagramXfrm::default(),
        proxy: local_addr
    };
    let ip = IPEndpointAddr::ip(IpAddr::from([0x01, 0x02, 0x03, 0x04]));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let data = [0xde, 0xad, 0xc0, 0xde];
    let (buf, local) = xfrm.wrap(&data, endpoint).expect("Expected success");
    let expected = [
        0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37, 0xde, 0xad,
        0xc0, 0xde
    ];
    let payload = buf.expect("Expected some");

    assert_eq!(local, local_addr);
    assert_eq!(&payload, &expected);
}

#[test]
fn test_udp_xfrm_wrap_name() {
    let local_addr = IpAddr::from([0xf1, 0xf2, 0xf3, 0xf4]);
    let mut xfrm = SOCKS5UDPXfrm::Basic {
        inner: PassthruDatagramXfrm::default(),
        proxy: local_addr
    };
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let data = [0xde, 0xad, 0xc0, 0xde];
    let (buf, local) = xfrm.wrap(&data, endpoint).expect("Expected success");
    let expected = [
        0x00, 0x00, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37, 0xde,
        0xad, 0xc0, 0xde
    ];
    let payload = buf.expect("Expected some");

    assert_eq!(local, local_addr);
    assert_eq!(&payload, &expected);
}

#[test]
fn test_udp_xfrm_wrap_ipv6() {
    let local_addr = IpAddr::from([0xf1, 0xf2, 0xf3, 0xf4]);
    let mut xfrm = SOCKS5UDPXfrm::Basic {
        inner: PassthruDatagramXfrm::default(),
        proxy: local_addr
    };
    let ip = IPEndpointAddr::ip(IpAddr::from([
        0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34
    ]));
    let port = 0x1337;
    let endpoint = IPEndpoint::new(ip, port);
    let data = [0xde, 0xad, 0xc0, 0xde];
    let (buf, local) = xfrm.wrap(&data, endpoint).expect("Expected success");
    let expected = [
        0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14,
        0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x13, 0x37, 0xde, 0xad,
        0xc0, 0xde
    ];
    let payload = buf.expect("Expected some");

    assert_eq!(local, local_addr);
    assert_eq!(&payload, &expected);
}

#[test]
fn test_udp_xfrm_unwrap_ipv4() {
    let local_addr = IpAddr::from([0xf1, 0xf2, 0xf3, 0xf4]);
    let mut xfrm = SOCKS5UDPXfrm::Basic {
        inner: PassthruDatagramXfrm::default(),
        proxy: local_addr
    };
    let mut buf = [
        0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x37, 0xde, 0xad,
        0xc0, 0xde
    ];
    let (size, peer) =
        xfrm.unwrap(&mut buf, local_addr).expect("Expected success");
    let data = [0xde, 0xad, 0xc0, 0xde];
    let ip = IPEndpointAddr::ip(IpAddr::from([0x01, 0x02, 0x03, 0x04]));
    let port = 0x1337;

    assert_eq!(peer, IPEndpoint::new(ip, port));
    assert_eq!(size, 4);
    assert_eq!(&buf[0..4], &data[..]);
}

#[test]
fn test_udp_xfrm_unwrap_name() {
    let local_addr = IpAddr::from([0xf1, 0xf2, 0xf3, 0xf4]);
    let mut xfrm = SOCKS5UDPXfrm::Basic {
        inner: PassthruDatagramXfrm::default(),
        proxy: local_addr
    };
    let mut buf = [
        0x00, 0x00, 0x00, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44, 0x13, 0x37, 0xde,
        0xad, 0xc0, 0xde
    ];
    let (size, peer) =
        xfrm.unwrap(&mut buf, local_addr).expect("Expected success");
    let data = [0xde, 0xad, 0xc0, 0xde];
    let ip = IPEndpointAddr::name(String::from("ABCD"));
    let port = 0x1337;

    assert_eq!(peer, IPEndpoint::new(ip, port));
    assert_eq!(size, 4);
    assert_eq!(&buf[0..4], &data[..]);
}

#[test]
fn test_udp_xfrm_unwrap_ipv6() {
    let local_addr = IpAddr::from([0xf1, 0xf2, 0xf3, 0xf4]);
    let mut xfrm = SOCKS5UDPXfrm::Basic {
        inner: PassthruDatagramXfrm::default(),
        proxy: local_addr
    };
    let mut buf = [
        0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14,
        0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x13, 0x37, 0xde, 0xad,
        0xc0, 0xde
    ];
    let (size, peer) =
        xfrm.unwrap(&mut buf, local_addr).expect("Expected success");
    let data = [0xde, 0xad, 0xc0, 0xde];
    let ip = IPEndpointAddr::ip(IpAddr::from([
        0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34
    ]));
    let port = 0x1337;

    assert_eq!(peer, IPEndpoint::new(ip, port));
    assert_eq!(size, 4);
    assert_eq!(&buf[0..4], &data[..]);
}
