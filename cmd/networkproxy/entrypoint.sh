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

if "${SINK}" -check -socket "${SOCKET}"; then
    echo "varmor-proxy-entrypoint: ALS agent socket reachable at ${SOCKET}; node-central mode (runc)"
else
    echo "varmor-proxy-entrypoint: ALS agent socket unreachable at ${SOCKET}; starting in-sidecar audit sink (kata)"
    "${SINK}" -socket "${SOCKET}" &
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
