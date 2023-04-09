FROM ubuntu:jammy

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
	pkg-config make gcc gdb lcov valgrind vim curl iputils-ping wget \
	autoconf automake libtool \
	apache2 libapache2-mod-php apache2-dev \
	libssl-dev libjansson-dev libcurl4-openssl-dev check \
	libhiredis-dev libcjose-dev \
	libpcre2-dev zlib1g-dev git libpcre3-dev

RUN a2enmod proxy && a2enmod proxy_http && a2enmod ssl && a2ensite default-ssl

COPY . /root/mod_auth_openidc

#RUN cd /root && \
#       git clone https://github.com/OpenIDC/mod_auth_openidc.git && \
#        cd mod_auth_openidc && \
#        git checkout v2.4.13.2

RUN cd /root/mod_auth_openidc && \
	./autogen.sh && \
	./configure CFLAGS="-g -O0" LDFLAGS="-lrt" && \
	make clean && make all test/test

RUN cd /root/mod_auth_openidc && \
	mkdir -p /etc/apache2/modules/ && \
	cp .libs/mod_auth_openidc.so /etc/apache2/modules/

RUN touch /etc/apache2/conf-available/openidc.conf && \
	a2enconf openidc
RUN /usr/sbin/apache2ctl start

RUN echo "<html><body>oh no, a 401 error occurred</body><html>" > /var/www/html/error401.html

RUN mkdir -p /var/www/html/protected && \
	echo "<html><body><h1>Hello, <?php echo(\$_SERVER['REMOTE_USER']) ?></h1><pre><?php print_r(array_map(\"htmlentities\", apache_request_headers())); ?></pre><a href=\"/protected/redirect_uri?logout=https%3A%2F%2Flocalhost.zmartzone.eu%2Floggedout.html\">Logout</a><?php phpinfo() ?></body></html>" >  /var/www/html/protected/index.php && \
	mkdir -p /var/www/html/api && cp /var/www/html/protected/index.php /var/www/html/api

RUN chmod a+rx /root

ENTRYPOINT ["/bin/bash", "-c"]
