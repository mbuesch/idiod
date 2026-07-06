#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(dirname "$(realpath "$0")")"

. "$basedir/scripts/lib.sh"

[ -f "$basedir/Cargo.toml" ] || die "basedir sanity check failed"

cd "$basedir" || die "cd basedir failed."
cargo build || die "Cargo build (debug) failed."
cargo test || die "Cargo test failed."
if which cargo-auditable >/dev/null 2>&1; then
    cargo auditable build --release || die "Cargo build (release) failed."
    cargo audit --deny warnings bin \
        target/release/idiod \
        target/release/idiod-apache-logfilter \
        || die "Cargo audit failed."
else
    cargo build --release || die "Cargo build (release) failed."
fi

# vim: ts=4 sw=4 expandtab
