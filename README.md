[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/indiecert/auth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/indiecert/auth/?branch=master)

# Introduction
IndieCert is an authentication service using client certificates.

# Installation
RPM packages are available for Fedora and CentOS/RHEL. On Fedora:

    $ sudo dnf copr enable fkooman/php-base
    $ sudo dnf copr enable fkooman/indiecert
    $ sudo dnf install indiecert-auth

On CentOS:

    $ sudo yum install epel-release
    $ sudo curl -s -L -o /etc/yum.repos.d/fkooman-php-base-epel-7.repo https://copr.fedoraproject.org/coprs/fkooman/php-base/repo/epel-7/fkooman-php-base-epel-7.repo
    $ sudo curl -s -L -o /etc/yum.repos.d/fkooman-indiecert-epel-7.repo https://copr.fedoraproject.org/coprs/fkooman/indiecert/repo/epel-7/fkooman-indiecert-epel-7.repo
    $ sudo yum install indiecert-auth

Restart Apache:

    $ sudo service httpd restart

# Configuration
Initialize the database, by default this is SQLite. If you want to use any 
other database please first modify the configuration file
`/etc/indiecert-auth/config.yaml`.

    $ sudo -u apache indiecert-auth-init

# Production Deployment
In case you want to deploy IndieCert in production, you SHOULD use the RPM 
packages mentioned above, or build them yourself. 

The default (Apache) configuration will make IndieCert available under the 
`indiecert-auth` sub folder.

# Development
We assume that your web server runs under the `apache` user and your user 
account is called `fkooman` in group `fkooman`.

    $ cd /var/www
    $ sudo mkdir indiecert-auth
    $ sudo chown fkooman.fkooman indiecert-auth
    $ git clone https://github.com/indiecert/auth.git indiecert-auth
    $ cd indiecert-auth
    $ /path/to/composer.phar install
    $ mkdir -p data
    $ sudo chown -R apache.apache data
    $ sudo semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/indiecert-auth/data(/.*)?'
    $ sudo restorecon -R /var/www/indiecert-auth/data
    $ cp config/config.yaml.example config/config.yaml

Now to initialize the database:

    $ sudo -u apache bin/init

# License
Licensed under the GNU Affero General Public License as published by the Free 
Software Foundation, either version 3 of the License, or (at your option) any 
later version.

    https://www.gnu.org/licenses/agpl.html

This roughly means that if you use this software in your service you need to 
make the source code available to the users of your service (if you modify
it). Refer to the license for the exact details.
