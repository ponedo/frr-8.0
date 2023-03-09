FROM --platform=${TARGETPLATFORM} centos:centos7
ARG TARGETARCH
RUN cp -a /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
COPY ./docker/centos-7/CentOS-7-${TARGETARCH}.repo /etc/yum.repos.d/CentOS-Base.repo
RUN yum clean all
RUN yum makecache
RUN yum install -y epel-release \
        rpm-build autoconf automake libtool make \
        readline-devel texinfo net-snmp-devel groff pkgconfig \
        json-c-devel pam-devel bison flex pytest c-ares-devel \
        python3-devel python3-sphinx systemd-devel libcap-devel \
        wget sudo \
        https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-7-x86_64-Packages/libyang2-2.0.0.10.g2eb910e4-1.el7.x86_64.rpm \
        https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-7-x86_64-Packages/libyang2-devel-2.0.0.10.g2eb910e4-1.el7.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-110/CentOS-7-x86_64-Packages/librtr-0.7.0-1.el7.centos.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-110/CentOS-7-x86_64-Packages/librtr-devel-0.7.0-1.el7.centos.x86_64.rpm \
    && yum clean all
# Update pip
# RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output /tmp/get-pip.py && \
#         python2 /tmp/get-pip.py && \
#         rm -f  /tmp/get-pip.py && \
#         pip2 install ipaddr && \
#         pip2 install "pytest<5" && \
#         pip2 install "scapy>=2.4.2" && \
#         pip2 install exabgp==3.4.17
# Update gcc
RUN yum install -y centos-release-scl \
    && yum install -y devtoolset-8-gcc devtoolset-8-gcc-c++ \
        devtoolset-8-make devtoolset-8-binutils \
    && echo "source /opt/rh/devtoolset-8/enable" >> ~/.bashrc \
    && source ~/.bashrc \
    && yum clean all
        # source scl_source enable devtoolset-8 && \
        # scl enable devtoolset-8 -- bash

# Add user group
RUN groupadd -r -g 92 frr && \
      groupadd -r -g 85 frrvty && \
      useradd --system -g frr --home-dir /home/frr \
              --comment "FRR suite" --shell /bin/bash frr && \
      usermod -a -G frrvty frr && \
      useradd -d /var/run/exabgp/ -s /bin/false exabgp && \
      echo 'frr ALL = NOPASSWD: ALL' | tee /etc/sudoers.d/frr && \
      mkdir -p /home/frr && chown frr.frr /home/frr

# Own the config / PID files
RUN mkdir -p /etc/frr /var/run/frr
RUN chown -R frr:frr /etc/frr /var/run/frr

ARG PKGVER
ARG OPTIM_TAG
COPY . /src

RUN source ~/.bashrc \
    && cd /src \
    && ./bootstrap.sh \
    && ./configure CFLAGS="-$OPTIM_TAG -fno-omit-frame-pointer" \ 
        --bindir=/usr/bin \ 
        --sbindir=/usr/lib/frr \ 
        --sysconfdir=/etc/frr \ 
        --libdir=/usr/lib/frr \ 
        --libexecdir=/usr/lib/frr \ 
        --localstatedir=/var/run/frr \ 
        --with-moduledir=/usr/lib/frr/modules \ 
        --enable-snmp=agentx \ 
        --enable-multipath=64 \ 
        --enable-user=frr \ 
        --enable-group=frr \ 
        --enable-vty-group=frrvty \ 
        --disable-ldpd \ 
        --enable-fpm \ 
        --with-pkg-git-version \ 
        --with-pkg-extra-version="_git$PKGVER" \ 
        SPHINXBUILD=/usr/bin/sphinx-build \
    && make -j16 && make install \
    && rm -rf /src

RUN rm -rf /src && yum clean all
