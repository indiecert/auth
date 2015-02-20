# Introduction
IndieCert is an authentication service using client certificates. This 
includes a CA and an easy way to enroll clients.

# Installation
RPM packages are available for Fedora and CentOS/RHEL:

    $ sudo yum -y install yum-plugin-copr
    $ yum copr enable -y fkooman/php-base
    $ yum copr enable -y fkooman/php-relmeauth
    $ yum install -y indiecert

Restart Apache:

    $ sudo service httpd restart

# Configuration
Initialize the database, by default this is SQLite. If you want to use any 
other database please first modify the configuration file
`/etc/indiecert/config.ini`.

    $ sudo -u apache indiecert-init

Also make sure you configure the details for the providers you want to use 
with IndieCert in `/etc/indiecert/config.ini`.

# Development
We assume that your web server runs under the `apache` user and your user 
account is called `fkooman` in group `fkooman`.

    $ cd /var/www
    $ sudo mkdir indiecert
    $ sudo chown fkooman.fkooman indiecert
    $ git clone https://github.com/fkooman/indiecert.git
    $ cd indiecert
    $ /path/to/composer.phar install
    $ mkdir -p data
    $ sudo chown -R apache.apache data
    $ sudo semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/indiecert/data(/.*)?'
    $ sudo restorecon -R /var/www/indiecert/data
    $ cd config
    $ cp config.ini.default config.ini

Now to initialize the database:

    $ sudo -u apache bin/indiecert-init

# License
Licensed under the GNU Affero General Public License as published by the Free 
Software Foundation, either version 3 of the License, or (at your option) any 
later version.

    https://www.gnu.org/licenses/agpl.html

This roughly means that if you use this software in your service you need to 
make the source code available to the users of your service (if you modify
it). Refer to the license for the exact details.
