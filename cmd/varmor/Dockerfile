## Building AppArmor
FROM debian:10 as apparmor-builder

LABEL maintainer="weiwei.danny@bytedance.com"

ARG MAKECHECK

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y git python3-pip python3-dev swig bison flex dejagnu pyflakes3 autoconf libtool zlib1g-dev gettext
RUN pip3 install notify2 psutil python-config

RUN git clone https://gitlab.com/apparmor/apparmor.git
WORKDIR /apparmor
RUN git checkout apparmor-3.0
RUN cd ./libraries/libapparmor && \
    sh ./autogen.sh && \
    sh ./configure --prefix=/usr --with-perl --with-python && \
    make && if [ ${MAKECHECK} = "check" ]; then make check; fi && make install
RUN cd ./binutils && make && if [ ${MAKECHECK} = "check" ]; then make check; fi && make install
RUN cd ./parser && make && if [ ${MAKECHECK} = "check" ]; then make check; fi && make install
RUN cd ./utils && make && if [ ${MAKECHECK} = "check" ]; then make check PYFLAKES=/usr/bin/pyflakes3; fi && make install
RUN cd ./profiles && make && make install
# Set the AppArmor feature ABI file to our custom version, this will lock policy down to a given stable feature set.
RUN echo "policy-features=/etc/apparmor.d/abi/varmor" >> /etc/apparmor/parser.conf


## Building vArmor-ebpf
FROM ghcr.io/cilium/ebpf-builder:1695900694 as vArmor-ebpf-builder

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 90
RUN update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-17 90
ADD . /varmor
WORKDIR /varmor
RUN make build-ebpf


## Building vArmor
FROM golang:1.20-buster as vArmor-builder

LABEL maintainer="vArmor authors"

COPY --from=apparmor-builder /usr/lib/libapparmor.* /usr/lib/
COPY --from=apparmor-builder /usr/include/aalogparse /usr/include/aalogparse

ARG TARGETPLATFORM
ADD . /varmor
WORKDIR /varmor

COPY --from=vArmor-ebpf-builder /varmor/vArmor-ebpf/pkg/tracer/bpf_bpfel.go /varmor/internal/behavior/tracer
COPY --from=vArmor-ebpf-builder /varmor/vArmor-ebpf/pkg/tracer/bpf_bpfel.o /varmor/internal/behavior/tracer
COPY --from=vArmor-ebpf-builder /varmor/vArmor-ebpf/pkg/bpfenforcer/bpf_bpfel.go /varmor/pkg/lsm/bpfenforcer
COPY --from=vArmor-ebpf-builder /varmor/vArmor-ebpf/pkg/bpfenforcer/bpf_bpfel.o /varmor/pkg/lsm/bpfenforcer

RUN export GOOS=$(echo ${TARGETPLATFORM} | cut -d / -f1) && \
    export GOARCH=$(echo ${TARGETPLATFORM} | cut -d / -f2)
RUN go env
RUN go build -o /output/vArmor -v ./cmd/varmor/


## Packaging vArmor
FROM debian:10

LABEL maintainer="vArmor authors"

# Copy the varmor executable to the image
COPY --from=vArmor-builder /output/ /varmor
# Copy the AppArmor feature ABI file which used during development and testing the VarmorPolicy to the image
COPY --from=vArmor-builder /varmor/config/apparmor.d/abi/varmor /varmor/apparmor.d/abi/varmor

# Copy the AppArmor executables and tools to the image
COPY --from=apparmor-builder /etc/apparmor/parser.conf /etc/apparmor/parser.conf
COPY --from=apparmor-builder /etc/apparmor.d /varmor/apparmor.d
COPY --from=apparmor-builder /sbin/apparmor_parser /sbin/apparmor_parser
COPY --from=apparmor-builder /usr/bin/aa-enabled /usr/bin/aa-enabled
COPY --from=apparmor-builder /usr/bin/aa-exec /usr/bin/aa-exec
COPY --from=apparmor-builder /usr/bin/aa-features-abi /usr/bin/aa-features-abi
COPY --from=apparmor-builder /usr/sbin/aa-status /usr/sbin/aa-status
COPY --from=apparmor-builder /usr/lib/libapparmor.* /usr/lib/
COPY --from=apparmor-builder /usr/sbin/aa-remove-unknown /usr/sbin/aa-remove-unknown
COPY --from=apparmor-builder /lib/apparmor/rc.apparmor.functions /lib/apparmor/rc.apparmor.functions

USER 10001:10001
WORKDIR /varmor
ENTRYPOINT ["/vArmor"]
