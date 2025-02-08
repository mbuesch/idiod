// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    classifier::Classifier,
    nftables::NftFirewall,
    systemd::{SystemdSocket, systemd_notify_ready},
};
use anyhow::{self as ah, Context as _, format_err as err};
use std::{net::IpAddr, time::Instant};
use tokio::net::{UnixListener, UnixStream};

const RX_BUF_SIZE: usize = 4096;
const PROTOCOL_VERSION: &str = "idiod v1";

#[derive(Debug, Clone)]
pub struct Message<'a> {
    stamp: Instant,
    app: &'a str,
    net_addr: IpAddr,
    net_xfer: usize,
    path: &'a str,
}

impl<'a> Message<'a> {
    /// The time stamp of this message.
    pub fn stamp(&self) -> Instant {
        self.stamp
    }

    /// The application name.
    #[allow(dead_code)]
    pub fn app(&self) -> &'a str {
        self.app
    }

    /// The network address.
    pub fn net_addr(&self) -> IpAddr {
        self.net_addr
    }

    /// The network transfer size, in bytes.
    pub fn net_xfer(&self) -> usize {
        self.net_xfer
    }

    /// The logical path, if any. May be empty.
    pub fn path(&self) -> &'a str {
        self.path
    }
}

#[derive(Debug)]
pub struct UnixConn {
    stream: UnixStream,
}

impl UnixConn {
    fn new(stream: UnixStream) -> ah::Result<Self> {
        Ok(Self { stream })
    }

    async fn recv_msg(&mut self) -> ah::Result<Option<String>> {
        loop {
            self.stream.readable().await?;

            let mut buf = vec![0_u8; RX_BUF_SIZE];
            match self.stream.try_read(&mut buf) {
                Ok(n) => {
                    if n == 0 {
                        return Ok(None);
                    }
                    buf.truncate(n);
                    return Ok(Some(String::from_utf8(buf)?));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    pub async fn handle_messages(&mut self, cls: &Classifier, fw: &NftFirewall) -> ah::Result<()> {
        let Some(msg) = self.recv_msg().await? else {
            return Err(err!("Disconnected."));
        };
        let stamp = Instant::now();

        let mut fields = msg.split(';');

        let Some(version) = fields.next() else {
            return Err(err!("RX message: Missing version field."));
        };
        if version.trim() != PROTOCOL_VERSION {
            return Err(err!("RX message: Unsupported version: {version}"));
        }

        let Some(app) = fields.next() else {
            return Err(err!("RX message: Missing application field."));
        };
        let app = app.trim();

        let Some(net_addr) = fields.next() else {
            return Err(err!("RX message: Missing network address field."));
        };
        let Ok(net_addr) = net_addr.trim().parse::<IpAddr>() else {
            return Err(err!("RX message: Invalid network address field."));
        };

        let Some(net_xfer) = fields.next() else {
            return Err(err!("RX message: Missing network transfer size field."));
        };
        let Ok(net_xfer) = net_xfer.trim().parse::<usize>() else {
            return Err(err!("RX message: Invalid network transfer size field."));
        };

        let Some(path) = fields.next() else {
            return Err(err!("RX message: Missing path field."));
        };
        let path = path.trim();

        let msg = Message {
            stamp,
            app,
            net_addr,
            net_xfer,
            path,
        };

        cls.add(fw, &msg).await;

        Ok(())
    }
}

#[derive(Debug)]
pub struct UnixSock {
    listener: UnixListener,
}

impl UnixSock {
    pub async fn new() -> ah::Result<Self> {
        let sockets = SystemdSocket::get_all()?;
        if let Some(SystemdSocket::Unix(socket)) = sockets.into_iter().next() {
            println!("Using Unix socket from systemd.");

            socket
                .set_nonblocking(true)
                .context("Set socket non-blocking")?;
            let listener = UnixListener::from_std(socket)
                .context("Convert std UnixListener to tokio UnixListener")?;

            systemd_notify_ready()?;

            Ok(Self { listener })
        } else {
            Err(err!("Received an unusable socket from systemd."))
        }
    }

    /// Accept a connection on the Unix socket.
    pub async fn accept(&self) -> ah::Result<UnixConn> {
        let (stream, _addr) = self.listener.accept().await?;
        UnixConn::new(stream)
    }
}

// vim: ts=4 sw=4 expandtab
