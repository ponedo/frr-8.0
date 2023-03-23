FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn
# Update Ubuntu Software repository
RUN apt update && \
    apt-get install -y \
      git autoconf automake libtool make libreadline-dev texinfo \
      pkg-config libpam0g-dev libjson-c-dev bison flex python3-pytest \
      libc-ares-dev python3-dev libsystemd-dev python-ipaddress python3-sphinx \
      install-info build-essential libsystemd-dev libsnmp-dev perl \
      libcap-dev python2 libelf-dev \
      sudo gdb curl iputils-ping time \
      mininet iproute2 iperf \
      wget gawk && \
      curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output /tmp/get-pip.py && \
      python2 /tmp/get-pip.py && \
      rm -f  /tmp/get-pip.py && \
      pip2 install ipaddr && \
      pip2 install "pytest<5" && \
      pip2 install "scapy>=2.4.2" && \
      pip2 install exabgp==3.4.17

RUN groupadd -r -g 92 frr && \
      groupadd -r -g 85 frrvty && \
      adduser --system --ingroup frr --home /home/frr \
              --gecos "FRR suite" --shell /bin/bash frr && \
      usermod -a -G frrvty frr && \
      useradd -d /var/run/exabgp/ -s /bin/false exabgp && \
      echo 'frr ALL = NOPASSWD: ALL' | tee /etc/sudoers.d/frr && \
      mkdir -p /home/frr && chown frr.frr /home/frr

# Recompile glibc with frame pointer
RUN cd /opt && \
    wget https://mirrors.aliyun.com/gnu/glibc/glibc-2.34.tar.gz && \
    tar xzf glibc-2.34.tar.gz && \
    cd /opt/glibc-2.34 && \
    mkdir build && \
    cd build && \
    ../configure CFLAGS="-O2 -fno-omit-frame-pointer" --prefix=/usr && \
    make -j16 && \
    rm -rf /opt/glibc-2.34.tar.gz

ENV GLIBC=/opt/glibc-2.34/build
ARG LIB_PATH=/lib
ARG GLIBC_LIB_PATH=/lib
RUN LIB_PATH=$(grep -v '^#' $(cat /etc/ld.so.conf | grep 'include' | awk '{print $2}') | awk -F ':' '{print $2}' | paste -s -d ':') && \
    echo "export LIB_PATH_ENV=$LIB_PATH" >> /etc/environment && \
    GLIBC_LIB_PATH=${GLIBC}:${GLIBC}/math:${GLIBC}/elf:${GLIBC}/dlfcn:${GLIBC}/nss:${GLIBC}/nis:${GLIBC}/rt:${GLIBC}/resolv:${GLIBC}/nptl:${GLIBC}/dfp && \
    echo "export GLIBC_LIB_PATH_ENV=$GLIBC_LIB_PATH" >> /etc/environment

    # GLIBC_LIB_PATH=${GLIBC}:${GLIBC}/math:${GLIBC}/elf:${GLIBC}/dlfcn:${GLIBC}/nss:${GLIBC}/nis:${GLIBC}/rt:${GLIBC}/resolv:${GLIBC}/crypt:${GLIBC}/nptl:${GLIBC}/dfp && \

#for libyang 2
RUN apt-get install -y cmake libpcre2-dev

# USER frr:frr

# build and install libyang2
RUN . /etc/environment && \
    cd && pwd && ls -al && \
    git clone https://github.com/CESNET/libyang.git && \
    cd libyang && \
    git checkout v2.0.0 && \
    mkdir build; cd build && \
    cmake -DCMAKE_C_FLAGS="-Wl,-rpath=${GLIBC_LIB_PATH_ENV}:${LIB_PATH_ENV} -Wl,--dynamic-linker=${GLIBC}/elf/ld.so -O2 -fno-omit-frame-pointer" \
          -DCMAKE_INSTALL_PREFIX:PATH=/usr \
          -DCMAKE_BUILD_TYPE:String="Release" .. && \
    make -j16 && \
    sudo make install && \
    cd ../../ && rm -rf libyang

# COPY --chown=frr:frr . /home/frr/frr/
COPY . /home/frr/frr/

RUN cd /home/frr/ && ls -al && ls -al frr

RUN . /etc/environment && \
    cd /home/frr/frr/ && \
    ./bootstrap.sh && \
    ./configure CFLAGS="-Wl,-rpath=${GLIBC_LIB_PATH_ENV}:${LIB_PATH_ENV} -Wl,--dynamic-linker=${GLIBC}/elf/ld.so -O2 -fno-omit-frame-pointer" \
       --prefix=/usr \
       --localstatedir=/var/run/frr \
       --sbindir=/usr/lib/frr \
       --sysconfdir=/etc/frr \
       --enable-vtysh \
       --enable-pimd \
       --enable-sharpd \
       --enable-multipath=64 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-vty-group=frrvty \
       --enable-snmp=agentx \
       --with-pkg-extra-version=-my-manual-build && \
    make -j16 && \
    sudo make install

# RUN cd /home/frr/frr/ && make check || true

RUN ldconfig

COPY docker/ubuntu20-ci/docker-start /usr/sbin/docker-start
# CMD ["/usr/sbin/docker-start"]
