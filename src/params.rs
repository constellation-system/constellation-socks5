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

//! Parameters for instantiating a SOCKS5 protocol instance.
use std::fmt::Display;
use std::fmt::Formatter;
#[cfg(feature = "gssapi")]
use std::time::Duration;

#[cfg(feature = "gssapi")]
use constellation_common::config::authn::ClientGSSAPIConfig;
#[cfg(feature = "gssapi")]
use constellation_common::config::authn::GSSAPISecurity;
use constellation_common::net::IPEndpoint;

/// SOCKS5 password authentication parameters.
#[derive(Clone)]
pub struct SOCKS5PasswordParams {
    /// Username for password authentication.
    username: String,
    /// Password for password authentication.
    password: String
}

#[cfg(feature = "gssapi")]
/// SOCKS5 GSSAPI authentication parameters.
#[derive(Clone)]
pub struct SOCKS5GSSAPIParams {
    /// Client credential name.
    name: Option<String>,
    /// Service name.
    service: String,
    time_req: Option<Duration>,
    /// Optional GSSAPI bindings.
    bindings: Option<Vec<u8>>,
    /// GSSAPI security level.
    security: GSSAPISecurity
}

/// SOCKS5 protocol parameters.
#[derive(Clone)]
pub struct SOCKS5Params {
    /// Endpoint for the proxy.
    target: IPEndpoint,
    /// SOCKS5 command to send.
    cmd: SOCKS5Command,
    #[cfg(feature = "gssapi")]
    /// GSSAPI authentication parameters.
    gssapi: Option<SOCKS5GSSAPIParams>,
    /// Password authentication parameters.
    password: Option<SOCKS5PasswordParams>
}

/// Enum for SOCKS5 commands.
#[derive(Copy, Clone)]
pub enum SOCKS5Command {
    /// TCP connect command.
    Connect = 0x01,
    /// TCP bind command.
    Bind = 0x02,
    /// UDP associate command.
    Associate = 0x03
}

impl SOCKS5Params {
    /// Create parameters for the connect command, with no authentication.
    #[inline]
    pub fn connect_no_auth(target: IPEndpoint) -> SOCKS5Params {
        SOCKS5Params {
            target: target,
            cmd: SOCKS5Command::Connect,
            password: None,
            #[cfg(feature = "gssapi")]
            gssapi: None
        }
    }

    /// Create parameters for the connect command, with password
    /// authentication.
    #[inline]
    pub fn connect_password_auth(
        target: IPEndpoint,
        username: String,
        password: String
    ) -> SOCKS5Params {
        SOCKS5Params {
            target: target,
            cmd: SOCKS5Command::Connect,
            #[cfg(feature = "gssapi")]
            gssapi: None,
            password: Some(SOCKS5PasswordParams {
                username: username,
                password: password
            })
        }
    }

    #[cfg(feature = "gssapi")]
    /// Create parameters for the connect command, with GSSAPI
    /// authentication.
    #[inline]
    pub fn connect_gssapi_auth(
        target: IPEndpoint,
        gssapi: ClientGSSAPIConfig,
        bindings: Option<Vec<u8>>
    ) -> SOCKS5Params {
        SOCKS5Params {
            target: target,
            cmd: SOCKS5Command::Connect,
            password: None,
            gssapi: Some(SOCKS5GSSAPIParams::from_config(gssapi, bindings))
        }
    }

    /// Create parameters for the bind command, with no authentication.
    #[inline]
    pub fn bind_no_auth(target: IPEndpoint) -> SOCKS5Params {
        SOCKS5Params {
            target: target,
            cmd: SOCKS5Command::Bind,
            #[cfg(feature = "gssapi")]
            gssapi: None,
            password: None
        }
    }

    /// Create parameters for the bind command, with password
    /// authentication.
    #[inline]
    pub fn bind_password_auth(
        target: IPEndpoint,
        username: String,
        password: String
    ) -> SOCKS5Params {
        SOCKS5Params {
            target: target,
            cmd: SOCKS5Command::Bind,
            #[cfg(feature = "gssapi")]
            gssapi: None,
            password: Some(SOCKS5PasswordParams {
                username: username,
                password: password
            })
        }
    }

    #[cfg(feature = "gssapi")]
    /// Create parameters for the bind command, with GSSAPI
    /// authentication.
    #[inline]
    pub fn bind_gssapi_auth(
        target: IPEndpoint,
        gssapi: ClientGSSAPIConfig,
        bindings: Option<Vec<u8>>
    ) -> SOCKS5Params {
        SOCKS5Params {
            target: target,
            cmd: SOCKS5Command::Bind,
            password: None,
            gssapi: Some(SOCKS5GSSAPIParams::from_config(gssapi, bindings))
        }
    }

    /// Create parameters for the UDP associate command, with no
    /// authentication.
    #[inline]
    pub fn assoc_no_auth(target: IPEndpoint) -> SOCKS5Params {
        SOCKS5Params {
            target: target,
            cmd: SOCKS5Command::Associate,
            #[cfg(feature = "gssapi")]
            gssapi: None,
            password: None
        }
    }

    /// Create parameters for the UDP associate command, with password
    /// authentication.
    #[inline]
    pub fn assoc_password_auth(
        target: IPEndpoint,
        username: String,
        password: String
    ) -> SOCKS5Params {
        SOCKS5Params {
            target: target,
            cmd: SOCKS5Command::Associate,
            #[cfg(feature = "gssapi")]
            gssapi: None,
            password: Some(SOCKS5PasswordParams {
                username: username,
                password: password
            })
        }
    }

    #[cfg(feature = "gssapi")]
    /// Create parameters for the UDP associate command, with GSSAPI
    /// authentication.
    #[inline]
    pub fn assoc_gssapi_auth(
        target: IPEndpoint,
        gssapi: ClientGSSAPIConfig,
        bindings: Option<Vec<u8>>
    ) -> SOCKS5Params {
        SOCKS5Params {
            target: target,
            cmd: SOCKS5Command::Associate,
            password: None,
            gssapi: Some(SOCKS5GSSAPIParams::from_config(gssapi, bindings))
        }
    }

    /// Get the SOCKS5 command to be executed.
    #[inline]
    pub fn cmd(&self) -> &SOCKS5Command {
        &self.cmd
    }

    /// Get the password authentication parameters, if they exist.
    #[inline]
    pub fn password(&self) -> Option<&SOCKS5PasswordParams> {
        self.password.as_ref()
    }

    #[cfg(feature = "gssapi")]
    /// Get the GSSAPI authentication parameters, if they exist.
    #[inline]
    pub fn gssapi(&self) -> Option<&SOCKS5GSSAPIParams> {
        self.gssapi.as_ref()
    }

    /// Get the target endpoint address.
    #[inline]
    pub fn target(&self) -> &IPEndpoint {
        &self.target
    }
}

impl SOCKS5PasswordParams {
    /// Get the username.
    #[inline]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the password.
    #[inline]
    pub fn password(&self) -> &str {
        &self.password
    }
}

#[cfg(feature = "gssapi")]
impl SOCKS5GSSAPIParams {
    /// Convert from a [ClientGSSAPIConfig].
    #[inline]
    fn from_config(
        config: ClientGSSAPIConfig,
        bindings: Option<Vec<u8>>
    ) -> SOCKS5GSSAPIParams {
        let (name, service, time_req, security) = config.take();
        let service = service.unwrap_or(String::from("socks5"));

        SOCKS5GSSAPIParams {
            name: name,
            service: service,
            time_req: time_req,
            security: security,
            bindings: bindings
        }
    }

    /// Get the principal name, if one is set.
    ///
    /// If this is not set, the system will automatically select a
    /// principal name.
    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the service principal to which to connect.
    #[inline]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Get the GSSAPI security level.
    #[inline]
    pub fn security(&self) -> &GSSAPISecurity {
        &self.security
    }

    #[inline]
    pub fn time_req(&self) -> Option<Duration> {
        self.time_req
    }

    #[inline]
    pub fn bindings(&self) -> Option<&[u8]> {
        self.bindings.as_deref()
    }
}

impl Display for SOCKS5Command {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5Command::Connect => write!(f, "connect"),
            SOCKS5Command::Bind => write!(f, "bind"),
            SOCKS5Command::Associate => write!(f, "UDP associate")
        }
    }
}
