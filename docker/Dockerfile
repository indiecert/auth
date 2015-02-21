FROM       fedora:21
MAINTAINER François Kooman <fkooman@tuxed.net>

RUN yum -y update; yum clean all
RUN yum install -y mod_ssl yum-plugin-copr; yum clean all 

RUN yum copr enable -y fkooman/php-base
RUN yum copr enable -y fkooman/php-relmeauth

RUN yum install -y indiecert; yum clean all

# generate the server certificate
RUN openssl req -subj '/CN=dev.indiecert.net' -new -x509 -nodes -out /etc/pki/tls/certs/dev.indiecert.net.crt -keyout /etc/pki/tls/private/dev.indiecert.net.key

# empty the existing indiecert httpd config as it conflicts with dev.indiecert.net
RUN echo '' > /etc/httpd/conf.d/indiecert.conf

# add httpd config for dev.indiecert.net
ADD dev.indiecert.net-httpd.conf /etc/httpd/conf.d/dev.indiecert.net.conf

# generate a 1024 bit key, 2048 takes too long for just a Docker demo...
RUN sed -i 's/2048/1024/' /etc/indiecert/config.ini

# disable the certificate check for use within the docker image
RUN sed -i 's/;disableServerCertCheck/disableServerCertCheck/' /etc/indiecert/config.ini

USER apache

# Initialize CA and DB
RUN indiecert-init

USER root

EXPOSE 443
EXPOSE 80
ENTRYPOINT ["/usr/sbin/httpd"]
CMD ["-D", "FOREGROUND"]
