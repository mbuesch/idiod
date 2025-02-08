// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct Idiot {
    addr: IpAddr,
    timeout: Instant,
}

impl Idiot {
    pub fn new(addr: IpAddr, timeout: Instant) -> Self {
        Self { addr, timeout }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn is_timed_out(&self, now: Instant) -> bool {
        now >= self.timeout
    }
}

impl std::fmt::Display for Idiot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let now = Instant::now();
        let to = if self.timeout >= now {
            self.timeout - now
        } else {
            Duration::from_millis(0)
        };
        write!(f, "{} (+{}s)", self.addr, to.as_secs())
    }
}

// vim: ts=4 sw=4 expandtab
