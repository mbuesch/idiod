// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _};
use serde::Deserialize;
use std::{path::Path, time::Duration};

#[derive(Debug, Clone, Deserialize)]
pub struct BaseConfig {
    pub debug: i32,
    pub max_num_peers: u64,
    pub peer_timeout_secs: u64,
}

impl BaseConfig {
    pub fn peer_timeout(&self) -> Duration {
        Duration::from_secs(self.peer_timeout_secs)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitConfig {
    pub packets_per_sec: f32,
    pub timeout_secs: u64,
}

impl LimitConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PkgRateConfig {
    pub min_count: u64,
    pub rate_thres: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    pub pkgrate: PkgRateConfig,
    pub new_peer_rate_thres: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    pub path_allowlist: Vec<String>,
    pub firewall_block_timeout_base_secs: f64,
    pub firewall_block_timeout_max_secs: f64,
}

impl NetworkConfig {
    pub fn firewall_block_timeout_base(&self) -> Duration {
        Duration::from_secs_f64(self.firewall_block_timeout_base_secs)
    }

    pub fn firewall_block_timeout_max(&self) -> Duration {
        Duration::from_secs_f64(self.firewall_block_timeout_max_secs)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScoringConfig {
    pub min: f32,
    pub max: f32,
    pub idiot_thres: f32,
    pub decay_interval_secs: f64,
    pub decay_fact: f32,
    pub decay: f32,
    pub bad_base_fact: f32,
    pub bad_pkg_rate: f32,
}

impl ScoringConfig {
    pub fn decay_interval(&self) -> Duration {
        Duration::from_secs_f64(self.decay_interval_secs)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub base: BaseConfig,
    pub limit: LimitConfig,
    pub peer: PeerConfig,
    pub net: NetworkConfig,
    pub score: ScoringConfig,
}

impl Config {
    pub fn new_parse_file(path: &Path) -> ah::Result<Self> {
        let data = std::fs::read_to_string(path).context("Read configuration file")?;
        let this = toml::from_str(&data).context("Parse configuration file")?;
        Ok(this)
    }

    pub fn parse_file(&mut self, path: &Path) -> ah::Result<()> {
        *self = Self::new_parse_file(path)?;
        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
