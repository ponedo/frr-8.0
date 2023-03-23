# This stage builds an rpm from the source
FROM centos:centos7 as centos-7-builder
RUN yum install -y epel-release
RUN yum install -y rpm-build autoconf automake libtool make \
        readline-devel texinfo net-snmp-devel groff pkgconfig \
        json-c-devel pam-devel bison flex pytest c-ares-devel \
        python3-devel python3-sphinx systemd-devel libcap-devel \
        wget sudo \
        https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-7-x86_64-Packages/libyang2-2.0.0.10.g2eb910e4-1.el7.x86_64.rpm \
        https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-7-x86_64-Packages/libyang2-devel-2.0.0.10.g2eb910e4-1.el7.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-110/CentOS-7-x86_64-Packages/librtr-0.7.0-1.el7.centos.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-110/CentOS-7-x86_64-Packages/librtr-devel-0.7.0-1.el7.centos.x86_64.rpm

COPY . /src
ARG PKGVER

# Update gcc
RUN yum install -y centos-release-scl
RUN yum install -y devtoolset-8-gcc devtoolset-8-gcc-c++ \
        devtoolset-8-make devtoolset-8-binutils
RUN echo "source /opt/rh/devtoolset-8/enable" >> ~/.bashrc && \
        source ~/.bashrc
        # source scl_source enable devtoolset-8 && \
        # scl enable devtoolset-8 -- bash

# Reinstall glibc
RUN cd /opt && \
        wget https://mirrors.aliyun.com/gnu/glibc/glibc-2.29.tar.gz
RUN cd /opt && tar xzf glibc-2.29.tar.gz
RUN source ~/.bashrc && \
        cd /opt/glibc-2.29 && \
        mkdir build && \
        cd build && \
        ../configure CFLAGS="-O2 -fno-omit-frame-pointer" --prefix=/usr && \
        ( make -j32 && make install || true ) && \
    rm -rf /opt/glibc-2.29

RUN source ~/.bashrc && \
    echo '%_smp_mflags %( echo "-j$(/usr/bin/getconf _NPROCESSORS_ONLN)"; )' >> /root/.rpmmacros \
    && cd /src \
    && ./bootstrap.sh \
    && ./configure CFLAGS="-O2 -fno-omit-frame-pointer" \
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
    && make -j16 dist \
    && cd / \
    && mkdir -p /rpmbuild/{SOURCES,SPECS} \
    && cp /src/frr*.tar.gz /rpmbuild/SOURCES \
    && cp /src/redhat/frr.spec /rpmbuild/SPECS \
    && rpmbuild \
        --define "_topdir /rpmbuild" \
        -ba /rpmbuild/SPECS/frr.spec

# This stage installs frr from the rpm
FROM centos:centos7
RUN mkdir -p /pkgs/rpm \
    && yum install -y https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-7-x86_64-Packages/libyang2-2.0.0.10.g2eb910e4-1.el7.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-110/CentOS-7-x86_64-Packages/librtr-0.7.0-1.el7.centos.x86_64.rpm

# Update gcc
RUN yum install -y centos-release-scl
RUN yum install -y devtoolset-8-gcc devtoolset-8-gcc-c++ \
        devtoolset-8-make devtoolset-8-binutils
RUN echo "source /opt/rh/devtoolset-8/enable" >> ~/.bashrc && \
        source ~/.bashrc
        # source scl_source enable devtoolset-8 && \
        # scl enable devtoolset-8 -- bash

# Reinstall glibc
# RUN cd /opt && \
#         wget https://mirrors.aliyun.com/gnu/glibc/glibc-2.29.tar.gz
COPY --from=centos-7-builder /opt/glibc-2.29/ /opt/glibc-2.29/
RUN cd /opt && tar xzf glibc-2.29.tar.gz
RUN source ~/.bashrc && \
        cd /opt/glibc-2.29 && \
        mkdir build && \
        cd build && \
        ../configure CFLAGS="-O2 -fno-omit-frame-pointer" --prefix=/usr && \
        ( make -j32 && make install || true ) && \
    rm -rf /opt/glibc-2.29.tar.gz

# # Install glibc
# COPY --from=centos-7-builder /opt/glibc-2.29/ /opt/glibc-2.29/

# RUN source ~/.bashrc && \
#     cd /opt/glibc-2.29/build && \
#     make install || true && \
#     cd / && \
#     rm -rf /opt/glibc-2.29

# Install FRR
COPY --from=centos-7-builder /rpmbuild/RPMS/ /pkgs/rpm/

RUN yum install -y /pkgs/rpm/*/*.rpm \
    && rm -rf /pkgs

# Own the config / PID files
RUN mkdir -p /var/run/frr
RUN chown -R frr:frr /etc/frr /var/run/frr

# # Add tini because no CentOS7 package
# ENV TINI_VERSION v0.19.0
# ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /sbin/tini
# RUN chmod +x /sbin/tini

# # Simple init manager for reaping processes and forwarding signals
# ENTRYPOINT ["/sbin/tini", "--"]

# Default CMD starts watchfrr
COPY docker/centos-7/docker-start /usr/lib/frr/docker-start
# CMD ["/usr/lib/frr/docker-start"]

RUN rm -f /etc/frr/frr.conf

# # Copy libc
# COPY --from=centos-7-builder /usr/lib64/libc.* /usr/lib64
# COPY --from=centos-7-builder /usr/share/info/libc.* /usr/share/info