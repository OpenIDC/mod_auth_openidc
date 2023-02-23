FROM ubuntu:focal

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
	pkg-config autoconf automake libtool \
	make gcc gdb lcov \
	valgrind apache2 check \
	libssl-dev libjansson-dev libcurl4-openssl-dev \
	apache2-dev libpcre2-dev \
	libcjose-dev libhiredis-dev \
	vim curl iputils-ping wget

RUN a2enmod ssl proxy proxy_http && \
	a2ensite default-ssl

COPY . mod_auth_openidc

RUN cd mod_auth_openidc && ./autogen.sh && \
	./configure CFLAGS="-g -O0" LDFLAGS="-lrt" && \
	make clean && make check && make install

RUN /usr/sbin/apache2ctl start
