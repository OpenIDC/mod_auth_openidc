FROM ubuntu:bionic
MAINTAINER hans.zandbelt@zmartzone.eu

RUN apt-get update && apt-get install -y pkg-config make gcc gdb lcov valgrind vim curl iputils-ping wget
RUN apt-get update && apt-get install -y autoconf automake libtool
RUN apt-get update && apt-get install -y libssl-dev libjansson-dev libcurl4-openssl-dev check
#RUN apt-get update && apt-get install -y libcjose-dev
RUN apt-get update && apt-get install -y apache2 apache2-dev

RUN apt-get update && apt-get install -y libpcre3-dev zlib1g-dev

RUN wget https://mod-auth-openidc.org/download/libcjose0_0.6.1.5-1~bionic+1_amd64.deb
RUN wget https://mod-auth-openidc.org/download/libcjose-dev_0.6.1.5-1~bionic+1_amd64.deb
RUN dpkg -i libcjose0_0.6.1.5-1~bionic+1_amd64.deb
RUN dpkg -i libcjose-dev_0.6.1.5-1~bionic+1_amd64.deb

RUN a2enmod ssl
RUN a2ensite default-ssl

RUN echo "/usr/sbin/apache2ctl start && tail -f /var/log/apache2/error.log " >> /root/run.sh
RUN chmod a+x /root/run.sh

COPY . /root/mod_auth_openidc
WORKDIR /root/mod_auth_openidc

RUN ./autogen.sh
RUN ./configure CFLAGS="-g -O0" LDFLAGS="-lrt"
#-I/usr/include/apache2
RUN make clean && make test 
RUN make install

WORKDIR /root

ADD openidc.conf /etc/apache2/conf-available
RUN a2enconf openidc
RUN /usr/sbin/apache2ctl start

# docker run -p 443:443 -it 749d1204d189 /bin/bash -c "source /etc/apache2/envvars && valgrind --leak-check=full /usr/sbin/apache2 -X"
