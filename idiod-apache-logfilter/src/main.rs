// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use regex::{Captures, Regex};
use std::{os::unix::fs::FileTypeExt as _, path::Path, sync::Arc, time::Duration};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt as _, AsyncWriteExt as _},
    net, runtime,
    signal::unix::{SignalKind, signal},
    sync::{self, broadcast},
    task,
    time::sleep,
};

const QUEUE_SIZE: usize = 256;

#[derive(Clone, Debug)]
struct LogLine(String);

#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Output log file.
    output_path: String,

    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,
}

async fn read_stdin(log_tx: Arc<broadcast::Sender<LogLine>>) -> ah::Result<()> {
    let reader = io::BufReader::new(io::stdin());
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await.context("Read from stdin")? {
        let mut line = LogLine(line);
        while let Err(l) = log_tx.send(line) {
            line = l.0;
            sleep(Duration::from_millis(10)).await;
        }
    }
    Ok(())
}

async fn filter_and_write_output(
    mut log_rx: broadcast::Receiver<LogLine>,
    mut out_file: fs::File,
) -> ah::Result<()> {
    let re_pw = Regex::new(r"(password|pw|pass|passw|passwd)=[^& \t\n]*")?;
    loop {
        let mut line = log_rx
            .recv()
            .await
            .context("Filter: Read from line buffer")?
            .0;
        line.push('\n');

        // Filter out passwords.
        let line = re_pw.replace_all(&line, |c: &Captures| format!("{}=***", &c[1]));

        out_file
            .write_all(line.as_bytes())
            .await
            .context("Write to OUTPUT-PATH file")?;
    }
}

fn str_find(s: &str, c: char, offs: usize) -> Option<usize> {
    if let Some(s) = s.get(offs..) {
        s.find(c).map(|pos| pos + offs)
    } else {
        None
    }
}

async fn send_to_idiod(
    mut log_rx: broadcast::Receiver<LogLine>,
    idiod_sock_path: &Path,
) -> ah::Result<()> {
    loop {
        let line = log_rx
            .recv()
            .await
            .context("Send: Read from line buffer")?
            .0;

        let Some(addr_end) = str_find(&line, ' ', 0) else {
            continue;
        };
        let Some(get_begin) = str_find(&line, '"', addr_end + 1) else {
            continue;
        };
        let Some(get_end) = str_find(&line, '"', get_begin + 1) else {
            continue;
        };
        let Some(status_end) = str_find(&line, ' ', get_end + 2) else {
            continue;
        };
        let Some(size_end) = str_find(&line, ' ', status_end + 1) else {
            continue;
        };

        let Some(addr) = line.get(..addr_end) else {
            continue;
        };
        let Some(get) = line.get(get_begin + 1..get_end - 1) else {
            continue;
        };
        let Some(size) = line.get(status_end + 1..size_end) else {
            continue;
        };

        let path = if let Some(path_begin) = str_find(get, ' ', 0) {
            get.get(path_begin + 1..).unwrap_or_default()
        } else {
            ""
        };

        let msg = format!("idiod v1; apache; {addr}; {size}; {path}");

        net::UnixStream::connect(idiod_sock_path)
            .await
            .context("Connect to idiod socket")?
            .write_all(msg.as_bytes())
            .await
            .context("Write to idiod socket")?;
    }
}

async fn is_socket(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path).await else {
        return false;
    };
    meta.file_type().is_socket()
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    let (exit_tx, mut exit_rx) = sync::mpsc::channel(1);
    let exit_tx = Arc::new(exit_tx);

    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();

    let out_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(&opts.output_path)
        .await
        .context("Open OUTPUT-PATH")?;

    let idiod_sock_path = Path::new("/run/idiod/idiod.sock");
    let idiod_sock_path = if is_socket(idiod_sock_path).await {
        Some(idiod_sock_path)
    } else {
        None
    };

    let (log_tx, log_rx) = broadcast::channel(QUEUE_SIZE);
    let log_tx = Arc::new(log_tx);

    // Task: Write to log file.
    task::spawn({
        let exit_tx = Arc::clone(&exit_tx);
        async move {
            if let Err(e) = filter_and_write_output(log_rx, out_file).await {
                let _ = exit_tx.send(Err(e)).await;
            } else {
                unreachable!();
            }
        }
    });

    // Task: Send to idiod daemon.
    if let Some(idiod_sock_path) = idiod_sock_path {
        task::spawn({
            let log_rx = log_tx.subscribe();
            let exit_tx = Arc::clone(&exit_tx);
            async move {
                if let Err(e) = send_to_idiod(log_rx, idiod_sock_path).await {
                    let _ = exit_tx.send(Err(e)).await;
                } else {
                    unreachable!();
                }
            }
        });
    }

    // Task: Read from stdin.
    task::spawn({
        let log_tx = Arc::clone(&log_tx);
        let exit_tx = Arc::clone(&exit_tx);
        async move {
            if let Err(e) = read_stdin(log_tx).await {
                let _ = exit_tx.send(Err(e)).await;
            } else {
                eprintln!("CustomLog stdin closed.");
            }
        }
    });

    // Task: Main loop.
    tokio::select! {
        _ = sigterm.recv() => {
            eprintln!("SIGTERM: Terminating.");
            Ok(())
        }
        _ = sigint.recv() => {
            Err(err!("Interrupted by SIGINT."))
        }
        code = exit_rx.recv() => {
            code.unwrap_or_else(|| Err(err!("Unknown error code.")))
        }
    }
}

fn main() -> ah::Result<()> {
    let opts = Arc::new(Opts::parse());

    if opts.version {
        println!(
            "idiod-apache-logfilter version {}",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }

    runtime::Builder::new_multi_thread()
        .thread_keep_alive(Duration::from_millis(5000))
        .max_blocking_threads(6)
        .worker_threads(3)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
