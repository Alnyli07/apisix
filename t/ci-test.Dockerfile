FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV OPENRESTY_PREFIX=/usr/local/openresty
ENV PATH=$OPENRESTY_PREFIX/nginx/sbin:$OPENRESTY_PREFIX/luajit/bin:$OPENRESTY_PREFIX/bin:/usr/local/bin:$PATH

# Base dependencies
RUN apt-get update && apt-get install -y \
    wget curl git make gcc g++ unzip \
    libpcre3 libpcre3-dev libpcre2-dev \
    cpanminus automake autoconf libtool \
    software-properties-common gnupg2 sudo \
    && rm -rf /var/lib/apt/lists/*

# Install test-nginx perl deps
RUN cpanm --notest Test::Nginx IPC::Run LWP::UserAgent

# Install etcd
RUN wget -q https://github.com/etcd-io/etcd/releases/download/v3.5.4/etcd-v3.5.4-linux-amd64.tar.gz \
    && tar xzf etcd-v3.5.4-linux-amd64.tar.gz \
    && cp etcd-v3.5.4-linux-amd64/etcd* /usr/local/bin/ \
    && rm -rf etcd-v3.5.4-linux-amd64*

WORKDIR /apisix
COPY . /apisix/

# Use APISIX's own CI scripts to install runtime + deps
SHELL ["/bin/bash", "-c"]

RUN source ./.requirements \
    && export OPENRESTY_VERSION=source \
    && bash ./ci/linux-install-openresty.sh

RUN bash ./utils/linux-install-luarocks.sh

RUN source ./ci/common.sh \
    && export_or_prefix \
    && make deps

# Pin test-nginx version + toolkit (same as CI)
RUN git init \
    && git clone --depth 1 https://github.com/openresty/test-nginx.git test-nginx \
    && cd test-nginx \
    && git fetch --depth=1 origin ced30a31bafab6c68873efb17b6d80f39bcd95f5 \
    && git checkout ced30a31bafab6c68873efb17b6d80f39bcd95f5 \
    && cd /apisix/t \
    && git clone --depth 1 https://github.com/api7/test-toolkit.git toolkit

RUN cp conf/config.yaml.example conf/config.yaml \
    && chmod +x t/plugin/dpop.t

CMD ["bash", "-c", "\
    etcd --data-dir /tmp/etcd-data > /tmp/etcd.log 2>&1 & \
    sleep 3 && \
    source ./ci/common.sh && export_or_prefix && \
    make init && \
    FLUSH_ETCD=1 prove --timer -Itest-nginx/lib -I./ -r t/plugin/dpop.t 2>&1; \
    echo '--- Exit code:' $? \
"]
