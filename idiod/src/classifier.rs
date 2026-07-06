// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    config::Config,
    idiots::Idiot,
    nftables::{FirewallAdded, FwAction, NftFirewall},
    unix_sock::Message,
};
use movavg::MovAvg;
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    num::Saturating,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock};

const EVENTQ_SIZE: usize = 128;
const PKGRATE_WINDOW_SIZE: usize = 32;
const PKGRATE_LIM_FACT: f32 = 8.0;
const NEWPEERRATE_WINDOW_SIZE: usize = 24;
const NEWPEERRATE_LIM_FACT: f32 = 8.0;
const STATE_DUMP_INTERVAL: Duration = Duration::from_secs(60);

type EventQueue = arraydeque::ArrayDeque<PeerEvent, EVENTQ_SIZE, arraydeque::Wrapping>;

#[derive(Clone, Debug)]
struct Rate<const WINDOW_SIZE: usize> {
    avg: MovAvg<f32, f32, WINDOW_SIZE>,
    prev_stamp: Option<Instant>,
    limit: f32,
    count: Saturating<u16>,
}

impl<const WINDOW_SIZE: usize> Rate<WINDOW_SIZE> {
    pub fn new(limit: f32) -> Self {
        Self {
            avg: MovAvg::new(),
            prev_stamp: None,
            limit,
            count: Saturating(0),
        }
    }

    pub fn feed(&mut self, now: Instant) {
        if let Some(prev_stamp) = self.prev_stamp {
            if now > prev_stamp {
                let dur = (now - prev_stamp).as_secs_f64();
                let rate = (1.0 / dur).min(self.limit.into());
                self.avg.feed(rate as f32);
                self.prev_stamp = Some(now);
                self.count += 1;
            }
        } else {
            self.avg.feed(0.0);
            self.prev_stamp = Some(now);
            self.count += 1;
        }
    }

    pub fn get(&self) -> Option<f32> {
        self.avg.try_get().ok()
    }

    pub fn count(&self) -> usize {
        self.count.0.into()
    }
}

#[derive(Clone, Debug)]
struct PeerScore(f32);

impl PeerScore {
    pub fn new(conf: &Config) -> Self {
        Self(conf.score.min)
    }

    pub const fn score(&self) -> f32 {
        self.0
    }

    pub fn bad(&mut self, conf: &Config, fact: f32) {
        self.0 *= conf.score.bad_base_fact * fact;
        self.0 = self.0.clamp(conf.score.min, conf.score.max);
    }

    pub fn decay(&mut self, conf: &Config) {
        self.0 *= conf.score.decay_fact;
        self.0 -= conf.score.decay;
        self.0 = self.0.clamp(conf.score.min, conf.score.max);
    }

    pub fn is_an_idiot(&self, conf: &Config) -> bool {
        self.0 >= conf.score.idiot_thres
    }
}

#[derive(Clone, Debug)]
struct PeerEvent {
    stamp: Instant,
}

impl PeerEvent {
    pub const fn new(stamp: Instant) -> Self {
        Self { stamp }
    }
}

#[derive(Clone, Debug)]
struct PeerState {
    addr: IpAddr,
    events: EventQueue,
    pkg_rate: Rate<PKGRATE_WINDOW_SIZE>,
    score: PeerScore,
    blocked_count: Saturating<u16>,
}

impl PeerState {
    pub fn new(conf: &Config, addr: IpAddr) -> Self {
        let rate_thres = conf.peer.pkgrate.rate_thres;
        Self {
            addr,
            events: EventQueue::new(),
            pkg_rate: Rate::new(rate_thres * PKGRATE_LIM_FACT),
            score: PeerScore::new(conf),
            blocked_count: Saturating(0),
        }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn last_touched_time(&self) -> Instant {
        if let Some(last) = self.last_event() {
            last.stamp
        } else {
            Instant::now()
        }
    }

    pub fn last_event(&self) -> Option<&PeerEvent> {
        self.events.back()
    }

    pub fn add_event(&mut self, msg: &Message<'_>) {
        let stamp = msg.stamp();
        let net_xfer: u32 = msg.net_xfer().try_into().unwrap_or(u32::MAX);

        let _ = net_xfer; //TODO

        self.pkg_rate.feed(stamp);
        self.events.push_back(PeerEvent::new(stamp));
    }

    pub fn recalculate_score(&mut self, conf: &Config) {
        let old_score = self.score.score();

        if let Some(pkg_rate) = self.pkg_rate.get() {
            let min_count: usize = conf.peer.pkgrate.min_count.try_into().unwrap();
            let rate_thres = conf.peer.pkgrate.rate_thres;

            if self.pkg_rate.count() > min_count && pkg_rate >= rate_thres {
                println!(
                    "Packet rate {:.1} >= {:.1} for {}",
                    pkg_rate, rate_thres, self.addr
                );
                self.score.bad(conf, conf.score.bad_pkg_rate);
            }
        }

        let new_score = self.score.score();
        if old_score != self.score.score() {
            let addr = self.addr;
            println!("New score {new_score:.1} for {addr}");
        }
    }

    pub fn decay(&mut self, conf: &Config) {
        self.score.decay(conf);
    }

    pub fn is_an_idiot(&self, conf: &Config) -> bool {
        self.score.is_an_idiot(conf)
    }

    pub fn blocked(&mut self) -> u16 {
        self.blocked_count += 1;
        self.blocked_count.0
    }

    pub fn fw_block_timeout(&self, conf: &Config) -> Duration {
        let fact = 1_u32 << self.blocked_count.0.min(31);

        let timeout = conf.net.firewall_block_timeout_base().saturating_mul(fact);

        if timeout >= conf.net.firewall_block_timeout_max() {
            conf.net.firewall_block_timeout_max()
        } else {
            timeout
        }
    }

    pub fn is_timed_out(&self, conf: &Config, now: Instant) -> bool {
        if let Some(last) = self.last_event() {
            (now - last.stamp) >= conf.base.peer_timeout()
        } else {
            unreachable!();
        }
    }
}

#[derive(Debug)]
struct ClassifierInner {
    conf: Arc<RwLock<Config>>,
    peers: HashMap<IpAddr, PeerState>,
    new_peer_rate: Rate<NEWPEERRATE_WINDOW_SIZE>,
    next_decay: Instant,
    next_state_dump: Instant,
    global_limit_count: Saturating<u32>,
}

impl ClassifierInner {
    async fn new(conf: Arc<RwLock<Config>>) -> Self {
        let conf_clone = Arc::clone(&conf);
        let conf = conf.read().await;

        let max_num_peers: usize = conf.base.max_num_peers.try_into().unwrap();
        let new_peer_rate_thres = conf.peer.new_peer_rate_thres;
        let now = Instant::now();
        Self {
            conf: conf_clone,
            peers: HashMap::with_capacity(max_num_peers + 1),
            new_peer_rate: Rate::new(new_peer_rate_thres * NEWPEERRATE_LIM_FACT),
            next_decay: now,
            next_state_dump: now,
            global_limit_count: Saturating(0),
        }
    }

    async fn add(&mut self, fw: &NftFirewall, msg: &Message<'_>) {
        let conf = self.conf.read().await;

        let mut is_new_peer = false;
        let mut is_blocked = false;

        let peer = self.peers.entry(msg.net_addr()).or_insert_with(|| {
            if conf.base.debug >= 2 {
                println!("New peer {}", msg.net_addr());
            }
            self.new_peer_rate.feed(msg.stamp());
            is_new_peer = true;
            PeerState::new(&conf, msg.net_addr())
        });

        peer.add_event(msg);
        peer.recalculate_score(&conf);

        if peer.is_an_idiot(&conf) {
            let timeout = msg.stamp() + peer.fw_block_timeout(&conf);
            let idiot = Idiot::new(msg.net_addr(), timeout);

            match fw.add_idiot(&idiot, FwAction::Block).await {
                Err(e) => eprintln!("ERROR: Failed to block idiot: {e}"),
                Ok(FirewallAdded::NewEntry) => {
                    is_blocked = true;
                    let count = peer.blocked();
                    println!("Blocking {idiot} (#{count}).");
                }
                Ok(FirewallAdded::ExistedAlready) => {
                    is_blocked = true;
                }
            }
        }

        if is_new_peer
            && !is_blocked
            && self.new_peer_rate.count() > NEWPEERRATE_WINDOW_SIZE
            && let Some(new_peer_rate) = self.new_peer_rate.get()
            && new_peer_rate >= conf.peer.new_peer_rate_thres
        {
            let packets_per_sec = conf.limit.packets_per_sec;
            let timeout = msg.stamp() + conf.limit.timeout();

            match fw.add_global_limit(packets_per_sec, timeout).await {
                Err(e) => eprintln!("ERROR: Failed to install global limit rule: {e}"),
                Ok(FirewallAdded::NewEntry) => {
                    self.global_limit_count += 1;
                    println!(
                        "Very high new peer rate ({new_peer_rate:.1})! \
                        Limiting packet rate to {packets_per_sec:.1}/s"
                    );
                }
                Ok(FirewallAdded::ExistedAlready) => (),
            }
        }

        let peer_count = self.peers.len();
        let max_num_peers: usize = conf.base.max_num_peers.try_into().unwrap();
        if peer_count > max_num_peers {
            let reduce_to = (max_num_peers * 95) / 100;
            println!("Reducing peer count from {peer_count} to {reduce_to}.");

            let mut peers_tree = BTreeMap::new();
            for peer in self.peers.values() {
                peers_tree.insert(peer.last_touched_time(), peer.addr());
            }

            let now = Instant::now();
            for (last_touched_time, addr) in peers_tree.iter() {
                if self.peers.len() <= reduce_to {
                    break;
                }
                let age = (now - *last_touched_time).as_secs_f64();
                if conf.base.debug >= 2 {
                    println!("Pruning {addr} age {age:.1} s");
                }
                self.peers.remove(addr);
            }
        }
    }

    async fn tick(&mut self, _fw: &NftFirewall) {
        let conf = self.conf.read().await;

        let now = Instant::now();
        self.peers.retain(|_, peer| {
            let timed_out = peer.is_timed_out(&conf, now);
            if timed_out && conf.base.debug >= 2 {
                println!("Peer {} timed out", peer.addr());
            }
            !timed_out
        });

        if now >= self.next_decay {
            for peer in self.peers.values_mut() {
                peer.decay(&conf);
            }
            self.next_decay = now + conf.score.decay_interval();
        }

        if now >= self.next_state_dump {
            let peer_count = self.peers.len();
            let new_peer_rate = self.new_peer_rate.get().unwrap_or(0.0);
            let global_limit_count = self.global_limit_count.0;
            println!(
                "State: pc={peer_count} \
                 npr={new_peer_rate:.1} \
                 glc={global_limit_count}"
            );
            self.next_state_dump = now + STATE_DUMP_INTERVAL;
        }
    }
}

#[derive(Debug)]
pub struct Classifier {
    conf: Arc<RwLock<Config>>,
    inner: Mutex<ClassifierInner>,
}

impl Classifier {
    pub async fn new(conf: Arc<RwLock<Config>>) -> Self {
        let conf_inner = Arc::clone(&conf);
        Self {
            conf,
            inner: Mutex::new(ClassifierInner::new(conf_inner).await),
        }
    }

    pub async fn add(&self, fw: &NftFirewall, msg: &Message<'_>) {
        if self
            .conf
            .read()
            .await
            .net
            .path_allowlist
            .iter()
            .any(|path| msg.path().starts_with(path))
        {
            return; // allowed
        }

        self.inner.lock().await.add(fw, msg).await
    }

    pub async fn tick(&self, fw: &NftFirewall) {
        self.inner.lock().await.tick(fw).await
    }
}

// vim: ts=4 sw=4 expandtab
