#!/bin/sh
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
# User-run example for a known, nonsecret single-line request/reply protocol.
# The output describes the business reply, never the cause of a failure.
set -u
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    printf '%s\n' 'usage: sh tcp_probe.sh IP PORT REQUEST EXPECTED_LINE [TIMEOUT_SECONDS]' >&2
    exit 2
fi
ip=$1 port=$2 request=$3 expected=$4 duration=${5:-8}
case "$ip" in ''|*[!0-9a-fA-F:.]*) exit 2;; esac
case "$port:$duration" in *[!0-9:]*) exit 2;; esac
if ! [ "$port" -ge 1 ] 2>/dev/null || ! [ "$port" -le 65535 ] 2>/dev/null ||
   ! [ "$duration" -ge 1 ] 2>/dev/null || ! [ "$duration" -le 30 ] 2>/dev/null; then
    exit 2
fi
newline='
'
carriage=$(printf '\r')
case "$request:$expected" in *"$newline"*|*"$carriage"*) exit 2;; esac
if [ -z "$request" ] || [ -z "$expected" ] ||
   [ "${#request}" -gt 1024 ] || [ "${#expected}" -gt 1024 ]; then
    exit 2
fi
umask 077
work=$(busybox mktemp -d) || exit 4
trap 'busybox rm -rf "$work"' 0
printf '%s\n' "$expected" > "$work/expected"
# timeout targets nc directly; process reaping depends on the application image.
# head bounds saved output, including one extra byte to detect truncation.
{
    { printf '%s\n' "$request"; busybox sleep "$duration"; } |
        busybox timeout -k 1 "$duration" busybox nc -n -v -w "$duration" "$ip" "$port"
    printf '%s\n' "$?" > "$work/transport"
} | busybox head -c 4097 > "$work/reply"
transport=$(busybox cat "$work/transport" 2>/dev/null) || transport=unknown
printf 'probe_transport_exit=%s\nprobe_reply_begin\n' "$transport"
busybox cat "$work/reply"
printf '\nprobe_reply_end\n'
size=$(busybox wc -c < "$work/reply")
if [ "$size" -gt 4096 ]; then
    printf '%s\n' 'probe_reply=over_limit'
    exit 5
fi
if [ "$transport" != 0 ]; then
    printf '%s\n' 'probe_reply=transport_error'
    exit 4
fi
if busybox cmp -s "$work/expected" "$work/reply"; then
    printf '%s\n' 'probe_reply=matched'
    exit 0
fi
printf '%s\n' 'probe_reply=missing_or_mismatch'
exit 3
