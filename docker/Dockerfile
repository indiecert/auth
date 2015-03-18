FROM       fedora:21
MAINTAINER François Kooman <fkooman@tuxed.net>

RUN yum -y update; yum clean all
RUN yum install -y yum-plugin-copr; yum clean all 

RUN yum copr enable -y fkooman/php-base
RUN yum copr enable -y fkooman/php-relmeauth

RUN yum install -y mod_ssl indiecert; yum clean all

# generate the server certificate
RUN openssl req -subj '/CN=indiecert.example.org' -new -x509 -nodes -out /etc/pki/tls/certs/indiecert.example.org.crt -keyout /etc/pki/tls/private/indiecert.example.org.key

# empty the existing indiecert httpd config as it conflicts with indiecert.example.org
RUN echo '' > /etc/httpd/conf.d/indiecert.conf

# add httpd config for indiecert.example.org
ADD indiecert.example.org-httpd.conf /etc/httpd/conf.d/indiecert.example.org.conf

# Add CAcert as a valid CA (this is pointless here as we disable certificate
# check anyway in the next step, but for production we use this)
ADD CAcert.pem /etc/pki/ca-trust/source/anchors/CAcert.pem
RUN update-ca-trust

# disable the certificate check for use within the docker image, as there is
# no trusted certificate for "indiecert.example.org" so verification will fail...
RUN sed -i 's/;disableServerCertCheck/disableServerCertCheck/' /etc/indiecert/config.ini

USER apache

# Initialize CA and DB
RUN indiecert-init-ca
RUN indiecert-init-db

USER root

EXPOSE 443
EXPOSE 80
ENTRYPOINT ["/usr/sbin/httpd"]
CMD ["-D", "FOREGROUND"]
