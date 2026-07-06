#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(dirname "$(realpath "$0")")"

. "$basedir/scripts/lib.sh"

entry_checks()
{
    [ -d "$target" ] || die "idiod is not built! Run ./build.sh"
    [ "$(id -u)" = "0" ] || die "Must be root to install idiod."
}

install_dirs()
{
    do_install \
        -o root -g root -m 0755 \
        -d /opt/idiod/bin

    do_install \
        -o root -g root -m 0755 \
        -d /opt/idiod/etc
}

install_conf()
{
    if ! [ -e /opt/idiod/etc/idiod.toml ]; then
        do_install \
            -o root -g root -m 0644 \
            "$basedir/idiod/idiod.toml" \
            /opt/idiod/etc/idiod.toml
    fi
}

install_idiod()
{
    do_install \
        -o root -g root -m 0755 \
        "$target/idiod" \
        /opt/idiod/bin/

    do_install \
        -o root -g root -m 0644 \
        "$basedir/idiod/idiod.service" \
        /etc/systemd/system/

    do_install \
        -o root -g root -m 0644 \
        "$basedir/idiod/idiod.socket" \
        /etc/systemd/system/

    do_systemctl enable idiod.socket
    do_systemctl enable idiod.service
}

install_idiod_apache_logfilter()
{
    do_install \
        -o root -g root -m 0755 \
        "$target/idiod-apache-logfilter" \
        /opt/idiod/bin/
}

release="release"
while [ $# -ge 1 ]; do
    case "$1" in
        --debug|-d)
            release="debug"
            ;;
        --release|-r)
            release="release"
            ;;
        *)
            die "Invalid option: $1"
            ;;
    esac
    shift
done
target="$basedir/target/$release"

entry_checks
stop_services
install_dirs
install_conf
install_idiod
install_idiod_apache_logfilter
do_systemctl daemon-reload
start_services

# vim: ts=4 sw=4 expandtab
