[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/indiecert/auth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/indiecert/auth/?branch=master)

# Introduction
IndieCert is an authentication service using client certificates.

# Installation
RPM packages are available for Fedora and CentOS/RHEL. On Fedora:

    $ sudo dnf copr enable fkooman/php-base
    $ sudo dnf copr enable fkooman/indiecert
    $ sudo dnf install indiecert

On CentOS:

    $ sudo yum install epel-release
    $ sudo curl -s -L -o /etc/yum.repos.d/fkooman-php-base-epel-7.repo https://copr.fedoraproject.org/coprs/fkooman/php-base/repo/epel-7/fkooman-php-base-epel-7.repo
    $ sudo curl -s -L -o /etc/yum.repos.d/fkooman-indiecert-epel-7.repo https://copr.fedoraproject.org/coprs/fkooman/indiecert/repo/epel-7/fkooman-indiecert-epel-7.repo
    $ sudo yum install indiecert

Restart Apache:

    $ sudo service httpd restart

# Configuration
Initialize the database, by default this is SQLite. If you want to use any 
other database please first modify the configuration file
`/etc/indiecert/config.ini`.

    $ sudo -u apache indiecert-init-db

# Production Deployment
In case you want to deploy IndieCert in production, you SHOULD use the RPM 
packages mentioned above, or build them yourself. 

The default (Apache) configuration will make IndieCert available under the 
`indiecert` sub folder. If you want to deploy IndieCert on the root of a 
domain, please check the `Dockerfile` on `indiecert/docker` on what steps
to perform. It shows exactly what you should do on production environments, 
except disable the certificate check.

You can also run the Docker image in production, provided you mount 
`/var/lib/indiecert` somewhere in the host before starting the container to be
able to retain the data when the Docker image updates.

Also, make sure you apply security updates to your host and docker image!

# Development
We assume that your web server runs under the `apache` user and your user 
account is called `fkooman` in group `fkooman`.

    $ cd /var/www
    $ sudo mkdir indiecert
    $ sudo chown fkooman.fkooman indiecert
    $ git clone https://github.com/indiecert/auth.git
    $ cd indiecert
    $ /path/to/composer.phar install
    $ mkdir -p data
    $ sudo chown -R apache.apache data
    $ sudo semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/indiecert/data(/.*)?'
    $ sudo restorecon -R /var/www/indiecert/data
    $ cp config/config.ini.example config/config.ini

Now to initialize the database:

    $ sudo -u apache bin/indiecert-init-db

# License
Licensed under the GNU Affero General Public License as published by the Free 
Software Foundation, either version 3 of the License, or (at your option) any 
later version.

    https://www.gnu.org/licenses/agpl.html

This roughly means that if you use this software in your service you need to 
make the source code available to the users of your service (if you modify
it). Refer to the license for the exact details.
