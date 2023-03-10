FROM ubuntu:jammy

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
	pkg-config make gcc gdb lcov valgrind vim curl iputils-ping wget \
	autoconf automake libtool \
	apache2 libapache2-mod-php apache2-dev \
	libssl-dev libjansson-dev libcurl4-openssl-dev check \
	libhiredis-dev libcjose-dev \
	libpcre2-dev zlib1g-dev

RUN a2enmod ssl && a2ensite default-ssl

COPY . /root/mod_auth_openidc

RUN cd /root/mod_auth_openidc && \
	./autogen.sh && \
	./configure CFLAGS="-g -O0" LDFLAGS="-lrt" && \
	make clean && make check && \
	make install

RUN touch /etc/apache2/conf-available/openidc.conf && \
	a2enconf openidc
RUN /usr/sbin/apache2ctl start

RUN mkdir -p /var/www/html/protected && \
	echo "<html><body><h1>Hello, <?php echo(\$_SERVER['REMOTE_USER']) ?></h1><pre><?php print_r(array_map(\"htmlentities\", apache_request_headers())); ?></pre><a href=\"/protected/?logout=https%3A%2F%2Flocalhost.zmartzone.eu%2Floggedout.html\">Logout</a><?php phpinfo() ?></body></html>" >  /var/www/html/protected/index.php && \
	mkdir -p /var/www/html/api && cp /var/www/html/protected/index.php /var/www/html/api

RUN chmod a+rx /root

ENTRYPOINT ["/bin/bash", "-c"]
