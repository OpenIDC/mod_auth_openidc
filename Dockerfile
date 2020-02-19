FROM centos:latest

# systemd integration (see https://hub.docker.com/_/centos)
ENV container docker
RUN (cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == \
systemd-tmpfiles-setup.service ] || rm -f $i; done); \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*;
VOLUME [ "/sys/fs/cgroup" ]
CMD ["/usr/sbin/init"]

# enable powertools repo
RUN sed -i '/enabled\=0/s/0$/1/' /etc/yum.repos.d/CentOS-PowerTools.repo

# enable debuginfo repo
RUN sed -i '/enabled\=0/s/0$/1/' /etc/yum.repos.d/CentOS-Debuginfo.repo

# install dependencies
RUN yum install -y \
        bzip2 \ 
        gcc \
        gcc-c++ \
        make \
        expat-devel.x86_64 \
        pcre-devel.x86_64 \
        openssl-devel.x86_64 \
        libxml2-devel.x86_64 \
        yajl-devel.x86_64 \
        ruby-devel.x86_64 \
        zlib-devel.x86_64 \
        jansson-devel.x86_64 \
        libcurl-devel.x86_64 \
        autoconf \
        automake \
        gdb

# install debuginfo
RUN yum debuginfo-install -y \
        expat-2.2.5-3.el8.x86_64 \
        glibc-2.28-72.el8.x86_64 \
        jansson-2.11-3.el8.x86_64 \
        keyutils-libs-1.5.10-6.el8.x86_64 \
        krb5-libs-1.17-9.el8.x86_64 \
        libblkid-2.32.1-17.el8.x86_64 \
        libcap-2.26-1.el8.x86_64 \
        libcom_err-1.44.6-3.el8.x86_64 \
        libcurl-minimal-7.61.1-11.el8.x86_64 \
        libgcc-8.3.1-4.5.el8.x86_64 \
        libmount-2.32.1-17.el8.x86_64 \
        libnghttp2-1.33.0-1.el8_0.1.x86_64 \
        libselinux-2.9-2.1.el8.x86_64 \
        libuuid-2.32.1-17.el8.x86_64 \
        libxcrypt-4.1.1-4.el8.x86_64 \
        openssl-libs-1.1.1c-2.el8.x86_64 \
        pcre-8.42-4.el8.x86_64 \
        pcre2-10.32-1.el8.x86_64 \
        systemd-libs-239-18.el8_1.1.x86_64 \
        zlib-1.2.11-10.el8.x86_64

# download and install hiredis
RUN mkdir -p /usr/src/rpm
RUN curl -L -o /usr/src/rpm/hiredis-0.13.3-12.el8.x86_64.rpm \
        https://cbs.centos.org/kojifiles/packages/hiredis/0.13.3/12.el8/x86_64/hiredis-0.13.3-12.el8.x86_64.rpm
RUN curl -L -o /usr/src/rpm/hiredis-devel-0.13.3-12.el8.x86_64.rpm \
        https://cbs.centos.org/kojifiles/packages/hiredis/0.13.3/12.el8/x86_64/hiredis-devel-0.13.3-12.el8.x86_64.rpm
RUN curl -L -o /usr/src/rpm/hiredis-debuginfo-0.13.3-12.el8.x86_64.rpm \
        https://cbs.centos.org/kojifiles/packages/hiredis/0.13.3/12.el8/x86_64/hiredis-debuginfo-0.13.3-12.el8.x86_64.rpm
RUN curl -L -o /usr/src/rpm/hiredis-debugsource-0.13.3-12.el8.x86_64.rpm \
        https://cbs.centos.org/kojifiles/packages/hiredis/0.13.3/12.el8/x86_64/hiredis-debugsource-0.13.3-12.el8.x86_64.rpm
RUN yum install -y /usr/src/rpm/hiredis-0.13.3-12.el8.x86_64.rpm \
        /usr/src/rpm/hiredis-devel-0.13.3-12.el8.x86_64.rpm \
        /usr/src/rpm/hiredis-debuginfo-0.13.3-12.el8.x86_64.rpm \
        /usr/src/rpm/hiredis-debugsource-0.13.3-12.el8.x86_64.rpm

# download and install cjose
RUN curl -L -o /usr/src/rpm/cjose-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm \
        http://mirror.centos.org/centos/8/AppStream/x86_64/os/Packages/cjose-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm
RUN curl -L -o /usr/src/rpm/cjose-devel-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm \
        http://mirror.centos.org/centos/8/AppStream/x86_64/os/Packages/cjose-devel-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm
RUN curl -L -o /usr/src/rpm/cjose-debuginfo-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm \
        http://debuginfo.centos.org/8/x86_64/Packages/cjose-debuginfo-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm
RUN curl -L -o /usr/src/rpm/cjose-debugsource-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm \
        http://debuginfo.centos.org/8/x86_64/Packages/cjose-debugsource-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm
RUN yum install -y /usr/src/rpm/cjose-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm \
        /usr/src/rpm/cjose-devel-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm \
        /usr/src/rpm/cjose-debuginfo-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm \
        /usr/src/rpm/cjose-debugsource-0.6.1-2.module_el8.0.0+13+fe691f1d.x86_64.rpm

# compile apr
RUN mkdir -p /usr/src/apache
#RUN curl -L -o /usr/src/apache/apr-1.6.5.tar.bz2 \
#        https://downloads.apache.org/apr/apr-1.6.5.tar.bz2
#RUN tar -C /usr/src/apache -xjf /usr/src/apache/apr-1.6.5.tar.bz2
#RUN cd /usr/src/apache/apr-1.6.5 && \
#        ./configure --prefix=/usr/local/apr && \
#        make && \
#        make install && \
#        cd -

#RUN yum install -y apr-devel libuuid-devel redhat-rpm-config

# compile apr-util
#RUN curl -L -o /usr/src/apache/apr-util-1.6.1.tar.bz2 \
#        https://downloads.apache.org/apr/apr-util-1.6.1.tar.bz2
#RUN tar -C /usr/src/apache -xjf /usr/src/apache/apr-util-1.6.1.tar.bz2
#RUN cd /usr/src/apache/apr-util-1.6.1 && \
#        ./configure --prefix=/usr/local/apr --with-apr=/usr/local/apr && \
#        make && \
#        make install && \
#        cd -

#RUN cd /usr/src/apache/apr-util-1.6.1 && \
#        ./configure --prefix=/usr/local/apr --with-apr=/usr && \
#        make && \
#        make install && \
#        cd -

#RUN yum install -y apr-devel apr-util-devel redhat-rpm-config

# compile httpd
#RUN curl -L -o /usr/src/apache/httpd-2.4.41.tar.bz2 \
#        https://downloads.apache.org//httpd/httpd-2.4.41.tar.bz2
#RUN tar -C /usr/src/apache -xjf /usr/src/apache/httpd-2.4.41.tar.bz2
#RUN cd /usr/src/apache/httpd-2.4.41 && \
#        ./configure --prefix=/opt/apache-2.4.41 \
#            --with-apr=/usr/local/apr/bin/apr-1-config \
#            --with-apr-util=/usr/local/apr/bin/apu-1-config \
#            --enable-mpms-shared=event \
#            --enable-mods-shared=all \
#            --enable-nonportable-atomics=yes && \
#        make && \
#        make install && \
#        cd -
#RUN cd /usr/src/apache/httpd-2.4.41 && \
#        ./configure --prefix=/opt/apache-2.4.41 \
#            --with-apr-util=/usr/local/apr/bin/apu-1-config \
#            --enable-mpms-shared=event \
#            --enable-mods-shared=all \
#            --enable-nonportable-atomics=yes && \
#        make && \
#        make install && \
#        cd -

RUN yum install -y httpd mod_ssl httpd httpd-devel redhat-rpm-config

# compile mod_auth_openidc
RUN mkdir -p /usr/src/mod_auth_openidc
ADD . /usr/src/mod_auth_openidc
#RUN curl -L -o /usr/src/mod_auth_openidc/mod_auth_openidc-2.4.1.tar.gz \
#        https://github.com/zmartzone/mod_auth_openidc/releases/download/v2.4.1/mod_auth_openidc-2.4.1.tar.gz
#RUN tar -C /usr/src/mod_auth_openidc -xf /usr/src/mod_auth_openidc/mod_auth_openidc-2.4.1.tar.gz
#ENV APR_LIBS=-L/usr/local/apr/lib
#ENV APR_CFLAGS=-I/usr/local/apr/include
#RUN sed -i '1 s/^.*$/\#\!\/usr\/bin\/perl -w/' /opt/apache-2.4.41/bin/apxs
#RUN cd /usr/src/mod_auth_openidc/mod_auth_openidc-2.4.1 && \
#        ./autogen.sh && \
#        ./configure CFLAGS="-g" --with-apxs2=/opt/apache-2.4.41/bin/apxs \
#            --with-apr=/usr/local/apr/bin/apr-1-config \
#            --with-apr-util=/usr/local/apr/bin/apu-1-config && \
#        make && \
#        make install && \
#        cd -

ENV APXS2_OPTS="-S LIBEXECDIR=/usr/lib64/httpd/modules/"
RUN cd /usr/src/mod_auth_openidc && \
        ./autogen.sh && \
        ./configure CFLAGS="-g -I/usr/include/httpd" && \
        make clean && make && \
        make install && \
        cd -

#RUN cd /usr/src/mod_auth_openidc/mod_auth_openidc-2.4.1 && \
#        ./autogen.sh && \
#        ./configure CFLAGS="-g" --with-apxs2=/opt/apache-2.4.41/bin/apxs \
#            --with-apr-util=/usr/local/apr/bin/apu-1-config && \
#        make && \
#        make install && \
#        cd -

# create coredump directory
RUN mkdir -p /tmp/coredump
RUN chmod 0777 /tmp/coredump

# copy the httpd.conf
#COPY httpd.conf /opt/apache-2.4.41/conf/httpd.conf
COPY httpd.conf /etc/httpd/conf/httpd.conf

# set ulimit for apachectl
#RUN sed -i '1 a ulimit -c unlimited' /opt/apache-2.4.41/bin/apachectl
RUN sed -i '1 a ulimit -c unlimited' /usr/sbin/apachectl
