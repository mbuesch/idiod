// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod classifier;
mod config;
mod idiots;
mod nftables;
mod systemd;
mod unix_sock;

use crate::{
    classifier::Classifier,
    config::Config,
    nftables::NftFirewall,
    systemd::{systemd_notify_reload_done, systemd_notify_reload_start},
    unix_sock::UnixSock,
};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    runtime,
    signal::unix::{SignalKind, signal},
    sync::{self, RwLock},
    task,
};

const CONFIG_FILE: &str = "/opt/idiod/etc/idiod.toml";

#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,
}

async fn async_main(_opts: Arc<Opts>) -> ah::Result<()> {
    // Create async IPC channels.
    let (exit_sock_tx, mut exit_sock_rx) = sync::mpsc::channel(1);
    let exit_sock_tx = Arc::new(exit_sock_tx);

    // Register unix signal handlers.
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sighup = signal(SignalKind::hangup()).unwrap();

    let conf = Arc::new(RwLock::new(Config::new_parse_file(Path::new(CONFIG_FILE))?));

    let sock = UnixSock::new().await.context("Unix socket init")?;

    let cls = Arc::new(Classifier::new(Arc::clone(&conf)).await);

    let fw = Arc::new(NftFirewall::new().await.context("Nftables firewall")?);

    // Spawn task: Socket handler.
    task::spawn({
        let exit_sock_tx = Arc::clone(&exit_sock_tx);
        let cls = Arc::clone(&cls);
        let fw = Arc::clone(&fw);

        async move {
            loop {
                let exit_sock_tx = Arc::clone(&exit_sock_tx);
                let cls = Arc::clone(&cls);
                let fw = Arc::clone(&fw);

                match sock.accept().await {
                    Ok(mut conn) => {
                        // Socket connection handler.
                        task::spawn(async move {
                            if let Err(e) = conn.handle_messages(&cls, &fw).await {
                                eprintln!("Client error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        let _ = exit_sock_tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        }
    });

    // Task: Periodic worker.
    task::spawn({
        let exit_sock_tx = Arc::clone(&exit_sock_tx);
        let cls = Arc::clone(&cls);
        let fw = Arc::clone(&fw);

        async move {
            let mut interval = tokio::time::interval(Duration::from_millis(1000));
            loop {
                interval.tick().await;
                cls.tick(&fw).await;
                if let Err(e) = fw.remove_timed_out_idiots().await {
                    let _ = exit_sock_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    // Task: Main loop.
    let mut exitcode;
    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                eprintln!("SIGTERM: Terminating.");
                exitcode = Ok(());
                break;
            }
            _ = sigint.recv() => {
                exitcode = Err(err!("Interrupted by SIGINT."));
                break;
            }
            _ = sighup.recv() => {
                println!("Reloading configuration.");
                if let Err(e) = systemd_notify_reload_start() {
                    eprintln!("Reload: Failed to notify systemd (Reloading): {e}");
                }
                if let Err(e) = conf.write().await.parse_file(Path::new(CONFIG_FILE)) {
                    eprintln!("Failed to load configuration file: {e}");
                }
                if let Err(e) = fw.reload().await {
                    eprintln!("Failed to reload firewall rules: {e}");
                }
                if let Err(e) = systemd_notify_reload_done() {
                    eprintln!("Reload: Failed to notify systemd (MonotonicUsec): {e}");
                }
            }
            code = exit_sock_rx.recv() => {
                exitcode = code.unwrap_or_else(|| Err(err!("Unknown error code.")));
                break;
            }
        }
    }

    // Exiting...
    // Try to remove all firewall rules.
    {
        if let Err(e) = fw.shutdown().await {
            eprintln!("WARNING: Failed to remove firewall rules: {e:?}");
            if exitcode.is_ok() {
                exitcode = Err(err!("Failed to remove firewall rules"));
            }
        }
    }

    exitcode
}

fn main() -> ah::Result<()> {
    let opts = Arc::new(Opts::parse());

    if opts.version {
        println!("idiod version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    runtime::Builder::new_multi_thread()
        .thread_keep_alive(Duration::from_millis(5000))
        .max_blocking_threads(4)
        .worker_threads(2)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
