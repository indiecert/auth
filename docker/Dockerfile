FROM       fedora:21
MAINTAINER François Kooman <fkooman@tuxed.net>

RUN yum -y update; yum clean all
RUN yum install -y yum-plugin-copr; yum clean all 

RUN yum copr enable -y fkooman/php-base
RUN yum copr enable -y fkooman/php-relmeauth

RUN yum install -y mod_ssl php-pecl-zendopcache indiecert; yum clean all

# generate the server certificate
RUN openssl req -subj '/CN=indiecert.example' -new -x509 -nodes -out /etc/pki/tls/certs/indiecert.example.crt -keyout /etc/pki/tls/private/indiecert.example.key
RUN chmod 600 /etc/pki/tls/private/indiecert.example.key

# empty the existing indiecert httpd config as it conflicts with indiecert.example
RUN echo '' > /etc/httpd/conf.d/indiecert.conf

# add httpd config for indiecert.example
ADD indiecert.example-httpd.conf /etc/httpd/conf.d/indiecert.example.conf

# Set PHP timezone, to suppress errors in the log
RUN sed -i 's/;date.timezone =/date.timezone = UTC/' /etc/php.ini

# Add CAcert as a valid CA (this is pointless here as we disable certificate
# check anyway in the next step, but for production we use this)
ADD CAcert.pem /etc/pki/ca-trust/source/anchors/CAcert.pem
RUN update-ca-trust

# disable the certificate check for use within the docker image, as there is
# no trusted certificate for "indiecert.example" so verification will fail...
RUN sed -i 's/;disableServerCertCheck/disableServerCertCheck/' /etc/indiecert/config.ini

# enable Twig template cache
RUN sed -i 's/;templateCache/templateCache/' /etc/indiecert/config.ini

# recommendation from https://php.net/manual/en/opcache.installation.php
RUN sed -i 's/;opcache.revalidate_freq=2/opcache.revalidate_freq=60/' /etc/php.d/opcache.ini

USER apache

# Initialize CA and DB
RUN indiecert-init-ca
RUN indiecert-init-db

USER root

EXPOSE 443
EXPOSE 80
ENTRYPOINT ["/usr/sbin/httpd"]
CMD ["-D", "FOREGROUND"]
