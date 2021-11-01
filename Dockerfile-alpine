FROM alpine:3.10

ENV MOD_AUTH_OPENIDC_REPOSITORY https://github.com/zmartzone/mod_auth_openidc.git

ENV MOD_AUTH_OPENIDC_BRANCH master

ENV BUILD_DIR /tmp/mod_auth_openidc

ENV APACHE_LOG_DIR /var/log/apache2

ENV APACHE_DEFAULT_CONF /etc/apache2/httpd.conf

# add testing repository (for cjose library)
RUN echo "http://nl.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories

# ADD source
RUN mkdir ${BUILD_DIR}

# add dependencies, build and install mod_auth_openidc, need atomic operation for image size
RUN apk update && apk add --no-cache \
  apache2 \
  apache2-proxy \
  wget \
  jansson \
  hiredis \
  cjose \
  cjose-dev \
  git \
  autoconf \
  build-base \
  automake \
  curl \
  apache2-dev \
  curl-dev \
  pcre-dev \
  libtool \
  && \
  cd ${BUILD_DIR} && \
  git clone -b ${MOD_AUTH_OPENIDC_BRANCH} ${MOD_AUTH_OPENIDC_REPOSITORY} && \
  cd mod_auth_openidc && \
  ./autogen.sh && \
  ./configure CFLAGS="-g -O0" LDFLAGS="-lrt" && \
  make test && \
  make install && \
  cd ../.. && \
  rm -fr ${BUILD_DIR} && \
  apk del git cjose-dev apache2-dev autoconf automake build-base wget curl-dev pcre-dev libtool

# configure apache 
RUN  apk add --no-cache sed && \
  echo "LoadModule auth_openidc_module /usr/lib/apache2/mod_auth_openidc.so" >>  ${APACHE_DEFAULT_CONF} && \
  ln -sfT /dev/stderr "${APACHE_LOG_DIR}/error.log" && \
  ln -sfT /dev/stdout "${APACHE_LOG_DIR}/access.log" && \
  ln -sfT /dev/stdout "${APACHE_LOG_DIR}/other_vhosts_access.log" && \
  chown -R --no-dereference "apache:users" "${APACHE_LOG_DIR}" && \
  apk del sed

# https://httpd.apache.org/docs/2.4/stopping.html#gracefulstop
# stop gracefully when docker stops, create issue with interactive mode because it's the signal use by the docker engine on windows.
STOPSIGNAL WINCH

# port to expose, referes to the Listen 80 in the embedded httpd.conf
EXPOSE 80

# launch apache
CMD exec /usr/sbin/httpd -D FOREGROUND -f ${APACHE_DEFAULT_CONF}