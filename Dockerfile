FROM ubuntu:bionic
MAINTAINER hans.zandbelt@zmartzone.eu

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y pkg-config make gcc gdb lcov valgrind vim curl iputils-ping wget
RUN apt-get update && apt-get install -y autoconf automake libtool
RUN apt-get update && apt-get install -y libssl-dev libjansson-dev libcurl4-openssl-dev check
RUN apt-get update && apt-get install -y apache2 apache2-dev
RUN apt-get update && apt-get install -y libpcre3-dev zlib1g-dev
RUN apt-get update && apt-get install -y libapache2-mod-php libhiredis-dev

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

RUN mkdir -p /var/www/html/protected
RUN echo "<html><body><h1>Hello, <?php echo($_SERVER['REMOTE_USER']) ?></h1><pre><?php print_r(array_map(\"htmlentities\", apache_request_headers())); ?></pre><a href=\"/protected/?logout=https%3A%2F%2Flocalhost.zmartzone.eu%2Floggedout.html\">Logout</a></body></html>" >  /var/www/html/protected/index.php
RUN mkdir -p /var/www/html/api && cp /var/www/html/protected/index.php /var/www/html/api

# docker run -p 443:443 -it mod_auth_openidc /bin/bash -c "source /etc/apache2/envvars && valgrind --leak-check=full /usr/sbin/apache2 -X"
