## Custom vArmor Envoy image
##
## This image is 100% runtime-agnostic. It is the upstream Envoy image plus:
##   - the networkproxy-audit-sink mini binary (in-sidecar ALS sink for kata), and
##   - the entrypoint that connect(2)-checks the fixed ALS socket to decide whether
##     to start the sink (kata) or not (runc), then drops privileges and exec-s Envoy.
##
## The sink reuses the varmor-agent auditor code, which is NOT CGO-free: it links
## libapparmor and imports the generated eBPF bindings (pkg/lsm/bpfenforcer). So the
## builder stages below mirror cmd/varmor/Dockerfile to provide the native deps.

## Building AppArmor & libseccomp (native deps for the cgo auditor)
FROM debian:bookworm AS apparmor-libseccomp-builder

LABEL maintainer="vArmor authors"

RUN apt-get update && apt-get -y upgrade
RUN apt-get install --no-install-recommends -y git build-essential apache2-dev autoconf autoconf-archive automake bison dejagnu flex libpam-dev libtool pkg-config python3-all-dev python3-setuptools ruby-dev swig zlib1g-dev gperf

RUN git clone https://gitlab.com/apparmor/apparmor.git
WORKDIR /apparmor
RUN git checkout apparmor-3.1
RUN cd ./libraries/libapparmor && \
    sh ./autogen.sh && \
    sh ./configure --prefix=/usr --with-perl --with-python && \
    make && make install

RUN git clone https://github.com/seccomp/libseccomp.git /libseccomp
WORKDIR /libseccomp
RUN git checkout v2.6.0
RUN ./autogen.sh && ./configure --prefix=/usr && \
    make && make install


## Building vArmor-ebpf (generated bindings imported by the auditor)
FROM ghcr.io/cilium/ebpf-builder:1777990914 AS varmor-ebpf-builder

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-22 90
RUN update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-22 90
ADD . /varmor
WORKDIR /varmor
RUN make build-ebpf


## Building the networkproxy-audit-sink mini binary (cgo enabled)
FROM golang:1.25-bookworm AS sink-builder

LABEL maintainer="vArmor authors"

ARG TARGETOS
ARG TARGETARCH
ADD . /varmor
WORKDIR /varmor

COPY --from=apparmor-libseccomp-builder /usr/lib/libseccomp.* /usr/lib/
COPY --from=apparmor-libseccomp-builder /usr/include/seccomp* /usr/include/
COPY --from=apparmor-libseccomp-builder /usr/lib/libapparmor.* /usr/lib/
COPY --from=apparmor-libseccomp-builder /usr/include/aalogparse /usr/include/aalogparse
COPY --from=varmor-ebpf-builder /varmor/vArmor-ebpf/pkg/processtracer/bpf_bpfel.go /varmor/pkg/processtracer
COPY --from=varmor-ebpf-builder /varmor/vArmor-ebpf/pkg/processtracer/bpf_bpfel.o /varmor/pkg/processtracer
COPY --from=varmor-ebpf-builder /varmor/vArmor-ebpf/pkg/bpfenforcer/bpf_bpfel.go /varmor/pkg/lsm/bpfenforcer
COPY --from=varmor-ebpf-builder /varmor/vArmor-ebpf/pkg/bpfenforcer/bpf_bpfel.o /varmor/pkg/lsm/bpfenforcer
COPY --from=varmor-ebpf-builder /varmor/vArmor-ebpf/pkg/bpfenforcer/bpfloop_bpfel.go /varmor/pkg/lsm/bpfenforcer
COPY --from=varmor-ebpf-builder /varmor/vArmor-ebpf/pkg/bpfenforcer/bpfloop_bpfel.o /varmor/pkg/lsm/bpfenforcer

RUN apt-get update
RUN apt-get install -y libseccomp2 libseccomp-dev
RUN GOOS=${TARGETOS} && \
    GOARCH=${TARGETARCH} && \
    CGO_ENABLED=1 go build -o /output/networkproxy-audit-sink -v \
        -ldflags "-w" \
        ./cmd/networkproxy/


## Packaging: upstream Envoy image + sink + entrypoint
FROM envoyproxy/envoy:v1.38-latest

LABEL maintainer="vArmor authors"

ARG TARGETARCH

# The in-sidecar sink binary (cgo: links libapparmor/libseccomp at runtime).
COPY --from=sink-builder /output/networkproxy-audit-sink /usr/local/bin/networkproxy-audit-sink

# Runtime shared libraries required by the cgo sink.
COPY --from=apparmor-libseccomp-builder /usr/lib/libapparmor.* /usr/lib/
COPY --from=apparmor-libseccomp-builder /usr/lib/libseccomp.* /usr/lib/
RUN if [ "${TARGETARCH}" = "arm64" ]; then \
        cp /usr/lib/libapparmor.* /usr/lib/aarch64-linux-gnu/ 2>&1 || true; \
        cp /usr/lib/libseccomp.* /usr/lib/aarch64-linux-gnu/ 2>&1 || true; \
    else \
        cp /usr/lib/libapparmor.* /usr/lib/x86_64-linux-gnu/ 2>&1 || true; \
        cp /usr/lib/libseccomp.* /usr/lib/x86_64-linux-gnu/ 2>&1 || true; \
    fi
RUN ldconfig

# Runtime-agnostic entrypoint: connect-check -> (kata) start sink -> drop to
# Envoy uid -> exec envoy. su-exec ships in the upstream Envoy image.
COPY cmd/networkproxy/entrypoint.sh /usr/local/bin/varmor-proxy-entrypoint.sh
RUN chmod 0755 /usr/local/bin/varmor-proxy-entrypoint.sh

# Start as root so the entrypoint can bind the sink socket (kata) and then drop
# privileges DOWN to the Envoy uid. RunAsUser:0 is set at admission.
USER root
ENTRYPOINT ["/usr/local/bin/varmor-proxy-entrypoint.sh"]
