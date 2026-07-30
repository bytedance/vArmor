#!/bin/sh
# Copyright 2026 vArmor Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# varmor-proxy-entrypoint.sh is the ENTRYPOINT of the custom vArmor Envoy image.
# It makes the image 100% runtime-agnostic: the same image and the same Envoy
# config Secret (LDS/CDS/bootstrap always target the fixed ALS socket path) work
# on both runc and kata with zero fork.
#
# The container is started as root (RunAsUser:0 at admission) so this script can
# do its init and then drop privileges DOWN to the Envoy uid before exec-ing
# Envoy. It never needs to raise privileges.
#
# Runtime detection is a connect(2) self-check against the fixed ALS socket:
#   - runc: the node-central varmor-agent listens on the hostPath-shared socket,
#     so the check succeeds. No in-sidecar sink is needed; Envoy streams ALS to
#     the agent exactly as before (node-central path, zero change).
#   - kata: the sidecar runs inside a micro-VM and a hostPath UDS cannot be
#     connect(2)-ed across the VM/virtio-fs boundary, so the check fails. This
#     script then starts the in-sidecar audit sink (as root: it binds the same
#     socket path and chmods it 0666), which reuses the agent auditor code to
#     write enriched records to the sidecar violations.log inside the container.
#     Envoy then streams ALS to that in-sidecar socket instead.
#
# In both cases Envoy is finally exec-ed as the unprivileged Envoy uid, so the
# iptables uid-owner RETURN exemption (which matches the Envoy uid) keeps
# working and Envoy own traffic is never redirect-looped. The sink, although
# started as root, only uses the UDS (no TCP), so it is never redirected either.
set -e

SOCKET="${VARMOR_ALS_SOCKET:-/var/run/varmor/audit/als/als.sock}"
SINK="/usr/local/bin/networkproxy-audit-sink"
ENVOY_UID="${VARMOR_ENVOY_UID:-1337}"

# In-sidecar audit sink supervision knobs (see supervise_sink below).
#   SINK_BACKOFF_MAX     - upper bound (seconds) for the exponential restart delay.
#   SINK_HEALTHY_SECONDS - if the sink stayed up at least this long before dying,
#                          the next restart delay is reset to 1s (treat as a fresh
#                          transient failure rather than a crash-loop).
SINK_BACKOFF_MAX="${VARMOR_SINK_BACKOFF_MAX:-30}"
SINK_HEALTHY_SECONDS="${VARMOR_SINK_HEALTHY_SECONDS:-60}"

# drop_and_exec drops privileges to the Envoy uid and exec-s Envoy with the
# container Args ("$@"). su-exec is shipped in the upstream Envoy image; setpriv
# (util-linux) is kept as a fallback so the script is robust across base images.
drop_and_exec() {
    if command -v su-exec >/dev/null 2>&1; then
        exec su-exec "${ENVOY_UID}" envoy "$@"
    elif command -v setpriv >/dev/null 2>&1; then
        exec setpriv --reuid "${ENVOY_UID}" --regid "${ENVOY_UID}" --clear-groups envoy "$@"
    else
        echo "varmor-proxy-entrypoint: no privilege-drop tool (su-exec/setpriv) found" >&2
        exit 1
    fi
}

# supervise_sink keeps the in-sidecar audit sink alive for the whole lifetime of
# the container. Envoy is exec-ed below as the container main process (PID 1):
# Kubernetes only restarts a container when its main process exits. If the sink
# were a plain background job and later panicked or its UDS server died, the
# container would NOT restart; Envoy would keep streaming ALS to a socket nobody
# listens on and audit records would be lost silently with no self-healing.
# Respawning the sink here bounds that loss to a short window.
#
# Restart timing uses exponential backoff (1s, doubling, capped at
# SINK_BACKOFF_MAX): a one-off crash recovers fast (~1s, minimal audit loss),
# while a genuine crash-loop quickly backs off so it does not spam logs or spin
# the CPU. If the sink stayed up at least SINK_HEALTHY_SECONDS before dying it is
# treated as a fresh transient failure and the delay resets to 1s.
#
# Every respawn is logged to stderr (container logs) so failures stay visible and
# alertable: [WARN] for an ordinary self-healed restart, escalating to [ERROR]
# once the backoff reaches its cap (i.e. the sink is crash-looping and self-heal
# is not resolving it).
supervise_sink() {
    n=0
    delay=1
    while true; do
        start=$(date +%s)
        "${SINK}" -socket "${SOCKET}" || true
        ran=$(( $(date +%s) - start ))
        n=$((n + 1))

        # A sink that ran healthily for a while before dying is a fresh transient
        # failure, not a crash-loop: recover fast next time.
        if [ "${ran}" -ge "${SINK_HEALTHY_SECONDS}" ]; then
            delay=1
        fi

        level="WARN"
        if [ "${delay}" -ge "${SINK_BACKOFF_MAX}" ]; then
            level="ERROR"
        fi
        echo "[${level}] varmor-proxy-entrypoint: in-sidecar audit sink exited after ${ran}s (respawn #${n}); restarting in ${delay}s" >&2

        sleep "${delay}"
        delay=$((delay * 2))
        if [ "${delay}" -gt "${SINK_BACKOFF_MAX}" ]; then
            delay="${SINK_BACKOFF_MAX}"
        fi
    done
}

if "${SINK}" -check -socket "${SOCKET}"; then
    echo "varmor-proxy-entrypoint: ALS agent socket reachable at ${SOCKET}; node-central mode (runc)"
else
    echo "varmor-proxy-entrypoint: ALS agent socket unreachable at ${SOCKET}; starting in-sidecar audit sink (kata)"
    # Start the sink under a supervisor so it is respawned if it dies; Envoy
    # (PID 1) never sees the sink's death, so without this the socket would go
    # silently unserved. See supervise_sink() above for the full rationale.
    supervise_sink &
    # Wait (bounded, ~5s) until the sink is accepting connections so Envoy does
    # not lose the earliest violation events to connection retries.
    i=0
    while [ "${i}" -lt 50 ]; do
        if "${SINK}" -check -socket "${SOCKET}"; then
            echo "varmor-proxy-entrypoint: in-sidecar audit sink is ready"
            break
        fi
        i=$((i + 1))
        sleep 0.1
    done
fi

drop_and_exec "$@"
