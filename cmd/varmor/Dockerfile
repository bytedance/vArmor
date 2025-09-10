## Building AppArmor & libseccomp
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
RUN cd ./binutils && make && make install
RUN cd ./parser && make && make install
RUN cd ./utils && make && make install
RUN cd ./profiles && make && make install
# Set the AppArmor feature ABI file to our custom version, this will lock policy down to a given stable feature set.
RUN echo "policy-features=/etc/apparmor.d/abi/varmor" >> /etc/apparmor/parser.conf

RUN git clone https://github.com/seccomp/libseccomp.git /libseccomp
WORKDIR /libseccomp
RUN git checkout v2.6.0
RUN ./autogen.sh && ./configure --prefix=/usr && \
    make && make install


## Building vArmor-ebpf
FROM ghcr.io/cilium/ebpf-builder:1755266860 AS varmor-ebpf-builder

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-20 90
RUN update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-20 90
ADD . /varmor
WORKDIR /varmor
RUN make build-ebpf


## Building vArmor
FROM golang:1.24-bookworm AS varmor-builder

LABEL maintainer="vArmor authors"

ARG GITVERSION
ARG GITCOMMIT
ARG BUILDDATE
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

RUN apt-get update
RUN apt-get install -y libseccomp2 libseccomp-dev
RUN GOOS=${TARGETOS} && \
    GOARCH=${TARGETARCH} && \
    GOVERSION=$(go version | awk '{print $3}') && \
    go build -o /output/vArmor -v \
        -ldflags "-w -X 'k8s.io/client-go/pkg/version.gitVersion=${GITVERSION}' \
                     -X 'k8s.io/client-go/pkg/version.gitCommit=${GITCOMMIT}'   \
                     -X 'k8s.io/client-go/pkg/version.buildDate=${BUILDDATE}'  \
                     -X 'main.gitVersion=${GITVERSION}' \
                     -X 'main.gitCommit=${GITCOMMIT}' \
                     -X 'main.buildDate=${BUILDDATE}' \
                     -X 'main.goVersion=${GOVERSION}'" \
        ./cmd/varmor/


## Packaging vArmor
FROM debian:bookworm

LABEL maintainer="vArmor authors"

# Copy the varmor executable to the image
COPY --from=varmor-builder /output/ /varmor
# Copy the AppArmor feature ABI file which used during development and testing the VarmorPolicy to the image
COPY --from=varmor-builder /varmor/config/apparmor.d/abi/varmor /varmor/apparmor.d/abi/varmor
# Copy the AppArmor executables and tools to the image
COPY --from=apparmor-libseccomp-builder /etc/apparmor/parser.conf /etc/apparmor/parser.conf
COPY --from=apparmor-libseccomp-builder /etc/apparmor.d /varmor/apparmor.d
COPY --from=apparmor-libseccomp-builder /sbin/apparmor_parser /sbin/apparmor_parser
COPY --from=apparmor-libseccomp-builder /usr/bin/aa-enabled /usr/bin/aa-enabled
COPY --from=apparmor-libseccomp-builder /usr/bin/aa-exec /usr/bin/aa-exec
COPY --from=apparmor-libseccomp-builder /usr/bin/aa-features-abi /usr/bin/aa-features-abi
COPY --from=apparmor-libseccomp-builder /usr/sbin/aa-status /usr/sbin/aa-status
COPY --from=apparmor-libseccomp-builder /usr/lib/libapparmor.* /usr/lib/
COPY --from=apparmor-libseccomp-builder /usr/sbin/aa-remove-unknown /usr/sbin/aa-remove-unknown
COPY --from=apparmor-libseccomp-builder /lib/apparmor/rc.apparmor.functions /lib/apparmor/rc.apparmor.functions
# Copy the libseccomp libraries to the image
COPY --from=apparmor-libseccomp-builder /usr/lib/libseccomp.* /usr/lib/
RUN if [ ${TARGETARCH} = "arm64" ]; then \
        rm -f /usr/lib/aarch64-linux-gnu/libseccomp.*; \
        cp /usr/lib/libseccomp.* /usr/lib/aarch64-linux-gnu/; \
    else \
        rm -f /usr/lib/x86_64-linux-gnu/libseccomp.*; \
        cp /usr/lib/libseccomp.* /usr/lib/x86_64-linux-gnu/; \
    fi

USER 10001:10001
WORKDIR /varmor
