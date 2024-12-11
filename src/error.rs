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

//! Errors that can occur in the SOCKS5 protocol.
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;

use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;

/// Errors that can occur in the SOCKS5 negotiation protocol.
#[derive(Debug)]
pub enum SOCKS5Error {
    /// A low-level IO error occurred.
    IOError {
        /// The IO-level error.
        error: Error
    },
    #[cfg(feature = "gssapi")]
    /// A GSSAPI error occurred.
    GSSAPIError {
        /// The GSSAPI error.
        error: libgssapi::error::Error
    },
    #[cfg(feature = "gssapi")]
    /// GSSAPI security level negotiation failed.
    BadGSSAPISecLvl {
        /// The actual security level.
        seclvl: u8
    },
    #[cfg(feature = "gssapi")]
    /// Unexpected GSSAPI reply kind.
    BadGSSAPIReplyKind {
        /// The unexpected kind.
        kind: u8
    },
    /// Unknown authentication method.
    UnknownAuthNMethod {
        /// Authentication method code.
        method: u8
    },
    /// Wrong protocol version.
    BadVersion {
        /// The protocol version.
        version: u8
    },
    /// Wrong reserved value.
    BadReserved {
        /// The value in the reserved slot.
        reserved: u8
    },
    /// Unexpected command reply code.
    BadCmdReplyKind {
        /// The reply code.
        kind: u8
    },
    /// Unknown address type.
    BadAddrType {
        /// Address type.
        ty: u8
    },
    /// Couldn't parse DNS name.
    BadDNSName,
    /// Server rejected authentication methods.
    NoAuthNMethods,
    /// Authentication failed.
    AuthNFailed,
    /// String was too long.
    TooLong,
    /// Supplied message was too short.
    TooShort,
    /// Internal proxy server failure.
    ServerFailure,
    /// Proxy server reported permission denied.
    PermissionDenied,
    /// Proxy server reported network unreachable.
    NetworkUnreachable,
    /// Proxy server reported host unreachable.
    HostUnreachable,
    /// Proxy server reported connection refused.
    ConnectionRefused,
    /// Proxy server reported TTL expired;
    TTLExpired,
    /// Proxy server reported command not supported.
    CmdNotSupported,
    /// Proxy server reported address type not supported.
    AddrTypeNotSupported,
    /// Fragmentation was used, which is not supported.
    FragNotSupported,
    /// Mutex was poisoned.
    MutexPoison
}

/// Errors that can occur in the SOCKS5 UDP assocation and
/// encapsulation protocols.
pub enum SOCKS5UDPError<Inner> {
    /// Error in the inner encoding.
    Inner { inner: Inner },
    /// Error wrapping message.
    Wrap { error: SOCKS5WrapError }
}

/// Errors that can occur when encapsulating a SOCKS5 UDP message.
#[derive(Clone, Debug)]
pub enum SOCKS5WrapError {
    /// Wrong protocol version.
    BadVersion {
        /// The protocol version.
        version: u8
    },
    /// Wrong reserved value.
    BadReserved {
        /// The value in the reserved slot.
        reserved: u8
    },
    #[cfg(feature = "gssapi")]
    /// A GSSAPI error occurred.
    GSSAPIError {
        /// The GSSAPI error.
        error: libgssapi::error::Error
    },
    #[cfg(feature = "gssapi")]
    /// Unexpected GSSAPI reply kind.
    BadGSSAPIReplyKind {
        /// The unexpected kind.
        kind: u8
    },
    /// Unknown address type.
    BadAddrType {
        /// Address type.
        ty: u8
    },
    /// Couldn't parse DNS name.
    BadDNSName,
    /// Fragmentation was used, which is not supported.
    FragNotSupported,
    /// String was too long.
    NameTooLong,
    /// Supplied message was too short.
    TooShort,
    /// Mutex was poisoned.
    MutexPoison
}

impl<Inner> ScopedError for SOCKS5UDPError<Inner>
where
    Inner: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SOCKS5UDPError::Inner { inner } => inner.scope(),
            SOCKS5UDPError::Wrap { error } => error.scope()
        }
    }
}

impl ScopedError for SOCKS5WrapError {
    fn scope(&self) -> ErrorScope {
        match self {
            // Protocol errors from the other party that kill the session.
            SOCKS5WrapError::BadAddrType { .. } |
            SOCKS5WrapError::BadVersion { .. } |
            SOCKS5WrapError::BadReserved { .. } |
            SOCKS5WrapError::BadDNSName |
            SOCKS5WrapError::FragNotSupported => ErrorScope::Session,
            // Problems with messages being sent.
            SOCKS5WrapError::NameTooLong | SOCKS5WrapError::TooShort => {
                ErrorScope::Msg
            }
            // Fatal errors.
            SOCKS5WrapError::MutexPoison => ErrorScope::Unrecoverable,
            // GSSAPI errors that kill the session.
            #[cfg(feature = "gssapi")]
            SOCKS5WrapError::GSSAPIError { .. } |
            SOCKS5WrapError::BadGSSAPIReplyKind { .. } => ErrorScope::Session
        }
    }
}

impl ScopedError for SOCKS5Error {
    fn scope(&self) -> ErrorScope {
        match self {
            SOCKS5Error::IOError { error } => error.scope(),
            #[cfg(feature = "gssapi")]
            SOCKS5Error::GSSAPIError { .. } |
            SOCKS5Error::BadGSSAPIReplyKind { .. } => ErrorScope::Session,
            #[cfg(feature = "gssapi")]
            SOCKS5Error::BadGSSAPISecLvl { .. } => ErrorScope::External,
            // Protocol errors that kill the session.
            SOCKS5Error::UnknownAuthNMethod { .. } |
            SOCKS5Error::BadVersion { .. } |
            SOCKS5Error::BadCmdReplyKind { .. } |
            SOCKS5Error::BadAddrType { .. } |
            SOCKS5Error::BadReserved { .. } |
            SOCKS5Error::ServerFailure |
            SOCKS5Error::BadDNSName => ErrorScope::Session,
            // Issues with the other server or network.
            SOCKS5Error::NoAuthNMethods |
            SOCKS5Error::AuthNFailed |
            SOCKS5Error::PermissionDenied |
            SOCKS5Error::NetworkUnreachable |
            SOCKS5Error::HostUnreachable |
            SOCKS5Error::ConnectionRefused |
            SOCKS5Error::TTLExpired |
            SOCKS5Error::CmdNotSupported |
            SOCKS5Error::AddrTypeNotSupported => ErrorScope::External,
            // Message level errors.
            SOCKS5Error::TooLong |
            SOCKS5Error::TooShort |
            SOCKS5Error::FragNotSupported => ErrorScope::Msg,
            // Fatal errors.
            SOCKS5Error::MutexPoison => ErrorScope::Unrecoverable
        }
    }
}

impl From<SOCKS5WrapError> for SOCKS5Error {
    fn from(val: SOCKS5WrapError) -> SOCKS5Error {
        match val {
            SOCKS5WrapError::BadVersion { version } => {
                SOCKS5Error::BadVersion { version: version }
            }
            SOCKS5WrapError::BadReserved { reserved } => {
                SOCKS5Error::BadReserved { reserved: reserved }
            }
            SOCKS5WrapError::BadAddrType { ty } => {
                SOCKS5Error::BadAddrType { ty: ty }
            }
            SOCKS5WrapError::BadDNSName => SOCKS5Error::BadDNSName,
            SOCKS5WrapError::NameTooLong => SOCKS5Error::TooLong,
            SOCKS5WrapError::TooShort => SOCKS5Error::TooShort,
            SOCKS5WrapError::MutexPoison => SOCKS5Error::MutexPoison,
            SOCKS5WrapError::FragNotSupported => SOCKS5Error::FragNotSupported,
            #[cfg(feature = "gssapi")]
            SOCKS5WrapError::BadGSSAPIReplyKind { kind } => {
                SOCKS5Error::BadGSSAPIReplyKind { kind }
            }
            #[cfg(feature = "gssapi")]
            SOCKS5WrapError::GSSAPIError { error } => {
                SOCKS5Error::GSSAPIError { error }
            }
        }
    }
}

impl Display for SOCKS5Error {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5Error::IOError { error } => write!(f, "{}", error),
            SOCKS5Error::NoAuthNMethods => {
                write!(f, "no acceptable authentication methods")
            }
            SOCKS5Error::AuthNFailed => write!(f, "authentication failed"),
            SOCKS5Error::BadVersion { version } => {
                write!(f, "bad protocol version {}", version)
            }
            SOCKS5Error::BadReserved { reserved } => {
                write!(f, "bad reserved value ({})", reserved)
            }
            SOCKS5Error::BadAddrType { ty } => {
                write!(f, "bad address type ({})", ty)
            }
            SOCKS5Error::BadCmdReplyKind { kind } => {
                write!(f, "bad command reply kind ({})", kind)
            }
            SOCKS5Error::TooLong => write!(f, "string parameter too long"),
            SOCKS5Error::TooShort => write!(f, "message was too short"),
            SOCKS5Error::BadDNSName => {
                write!(f, "UTF-8 error while decoding DNS name")
            }
            SOCKS5Error::ServerFailure => {
                write!(f, "internal proxy server failure")
            }
            SOCKS5Error::PermissionDenied => write!(f, "permission denied"),
            SOCKS5Error::NetworkUnreachable => write!(f, "network unreachable"),
            SOCKS5Error::HostUnreachable => write!(f, "host unreachable"),
            SOCKS5Error::ConnectionRefused => write!(f, "connection refused"),
            SOCKS5Error::TTLExpired => write!(f, "TTL expired"),
            SOCKS5Error::AddrTypeNotSupported => {
                write!(f, "address type not supported")
            }
            SOCKS5Error::CmdNotSupported => write!(f, "command not supported"),
            SOCKS5Error::UnknownAuthNMethod { method } => {
                write!(f, "bad protocol version {}", method)
            }
            SOCKS5Error::FragNotSupported => {
                write!(f, "fragmentation not supported")
            }
            SOCKS5Error::MutexPoison => write!(f, "mutex poisoned"),
            #[cfg(feature = "gssapi")]
            SOCKS5Error::BadGSSAPIReplyKind { kind } => {
                write!(f, "bad GSSAPI reply kind ({})", kind)
            }
            #[cfg(feature = "gssapi")]
            SOCKS5Error::BadGSSAPISecLvl { seclvl } => {
                write!(f, "GSSAPI security level {} too low", seclvl)
            }
            #[cfg(feature = "gssapi")]
            SOCKS5Error::GSSAPIError { error } => {
                write!(f, "GSSAPI error ({})", error)
            }
        }
    }
}

impl<Inner> Debug for SOCKS5UDPError<Inner>
where
    Inner: Debug
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5UDPError::Inner { inner } => inner.fmt(f),
            SOCKS5UDPError::Wrap { error } => write!(f, "{}", error)
        }
    }
}

impl<Inner> Display for SOCKS5UDPError<Inner>
where
    Inner: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5UDPError::Inner { inner } => inner.fmt(f),
            SOCKS5UDPError::Wrap { error } => write!(f, "{}", error)
        }
    }
}

impl Display for SOCKS5WrapError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5WrapError::BadVersion { version } => {
                write!(f, "bad protocol version {}", version)
            }
            SOCKS5WrapError::BadReserved { reserved } => {
                write!(f, "bad reserved value ({})", reserved)
            }
            SOCKS5WrapError::BadAddrType { ty } => {
                write!(f, "bad address type ({})", ty)
            }
            SOCKS5WrapError::BadDNSName => {
                write!(f, "UTF-8 error while decoding DNS name")
            }
            SOCKS5WrapError::NameTooLong => write!(f, "DNS name too long"),
            SOCKS5WrapError::TooShort => write!(f, "message was too short"),
            SOCKS5WrapError::MutexPoison => write!(f, "mutex poisoned"),
            SOCKS5WrapError::FragNotSupported => {
                write!(f, "fragmentation not supported")
            }
            #[cfg(feature = "gssapi")]
            SOCKS5WrapError::BadGSSAPIReplyKind { kind } => {
                write!(f, "bad GSSAPI reply kind ({})", kind)
            }
            #[cfg(feature = "gssapi")]
            SOCKS5WrapError::GSSAPIError { error } => {
                write!(f, "GSSAPI error ({})", error)
            }
        }
    }
}
