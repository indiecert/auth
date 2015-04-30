%global github_owner     fkooman
%global github_name      indiecert

Name:       indiecert
Version:    0.4.2
Release:    1%{?dist}
Summary:    Authentication service using client certificates

Group:      Applications/Internet
License:    AGPLv3+
URL:        https://github.com/%{github_owner}/%{github_name}
Source0:    https://github.com/%{github_owner}/%{github_name}/archive/%{version}.tar.gz
Source1:    indiecert-httpd.conf
Source2:    indiecert-autoload.php

BuildArch:  noarch

Requires:   php >= 5.4
Requires:   php-openssl
Requires:   php-pdo
Requires:   httpd

Requires:   php-composer(guzzlehttp/guzzle) >= 4.0
Requires:   php-composer(guzzlehttp/guzzle) < 5.0
Requires:   php-composer(fkooman/json) >= 0.6.0
Requires:   php-composer(fkooman/json) < 0.7.0
Requires:   php-composer(fkooman/ini) >= 0.2.0
Requires:   php-composer(fkooman/ini) < 0.3.0
Requires:   php-composer(fkooman/rest) >= 0.8.1
Requires:   php-composer(fkooman/rest) < 0.9.0
Requires:   php-composer(fkooman/rest-plugin-indieauth) >= 0.2.2
Requires:   php-composer(fkooman/rest-plugin-indieauth) < 0.3.0
Requires:   php-composer(fkooman/rest-plugin-bearer) >= 0.4.0
Requires:   php-composer(fkooman/rest-plugin-bearer) < 0.5.0
Requires:   php-composer(fkooman/cert-parser) >= 0.1.8
Requires:   php-composer(fkooman/cert-parser) < 0.2.0

Requires:   php-pear(pear.twig-project.org/Twig) >= 1.15
Requires:   php-pear(pear.twig-project.org/Twig) < 2.0
Requires:   php-pear(phpseclib.sourceforge.net/File_X509) >= 0.3.9
Requires:   php-pear(phpseclib.sourceforge.net/File_X509) < 0.4.0
Requires:   php-pear(phpseclib.sourceforge.net/Crypt_RSA) >= 0.3.9
Requires:   php-pear(phpseclib.sourceforge.net/Crypt_RSA) < 0.4.0

#Starting F21 we can use the composer dependency for Symfony
#Requires:   php-composer(symfony/classloader) >= 2.3.9
#Requires:   php-composer(symfony/classloader) < 3.0
Requires:   php-pear(pear.symfony.com/ClassLoader) >= 2.3.9
Requires:   php-pear(pear.symfony.com/ClassLoader) < 3.0

Requires(post): policycoreutils-python
Requires(postun): policycoreutils-python

%description
IndieCert is an authentication service using client certificates. This 
includes a CA and an easy way to enroll clients.

%prep
%setup -qn %{github_name}-%{version}

sed -i "s|dirname(__DIR__)|'%{_datadir}/indiecert'|" bin/indiecert-init-ca
sed -i "s|dirname(__DIR__)|'%{_datadir}/indiecert'|" bin/indiecert-init-db
sed -i "s|dirname(__DIR__)|'%{_datadir}/indiecert'|" bin/indiecert-housekeeping

%build

%install
# Apache configuration
install -m 0644 -D -p %{SOURCE1} ${RPM_BUILD_ROOT}%{_sysconfdir}/httpd/conf.d/indiecert.conf

# Application
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/indiecert
cp -pr web views src ${RPM_BUILD_ROOT}%{_datadir}/indiecert

# use our own class loader
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/indiecert/vendor
cp -pr %{SOURCE2} ${RPM_BUILD_ROOT}%{_datadir}/indiecert/vendor/autoload.php

mkdir -p ${RPM_BUILD_ROOT}%{_bindir}
cp -pr bin/* ${RPM_BUILD_ROOT}%{_bindir}

# Config
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/indiecert
cp -p config/config.ini.default ${RPM_BUILD_ROOT}%{_sysconfdir}/indiecert/config.ini
ln -s ../../../etc/indiecert ${RPM_BUILD_ROOT}%{_datadir}/indiecert/config

# Data
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/lib/indiecert

%post
semanage fcontext -a -t httpd_sys_rw_content_t '%{_localstatedir}/lib/indiecert(/.*)?' 2>/dev/null || :
restorecon -R %{_localstatedir}/lib/indiecert || :

%postun
if [ $1 -eq 0 ] ; then  # final removal
semanage fcontext -d -t httpd_sys_rw_content_t '%{_localstatedir}/lib/indiecert(/.*)?' 2>/dev/null || :
fi

%files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/httpd/conf.d/indiecert.conf
%config(noreplace) %{_sysconfdir}/indiecert
%{_bindir}/indiecert-init-ca
%{_bindir}/indiecert-init-db
%{_bindir}/indiecert-housekeeping
%dir %{_datadir}/indiecert
%{_datadir}/indiecert/src
%{_datadir}/indiecert/vendor
%{_datadir}/indiecert/web
%{_datadir}/indiecert/views
%{_datadir}/indiecert/config
%dir %attr(0700,apache,apache) %{_localstatedir}/lib/indiecert
%doc README.md agpl-3.0.txt composer.json config/

%changelog
* Thu Apr 30 2015 François Kooman <fkooman@tuxed.net> - 0.4.2-1
- update to 0.4.2

* Sun Apr 26 2015 François Kooman <fkooman@tuxed.net> - 0.4.1-1
- update to 0.4.1

* Sat Apr 25 2015 François Kooman <fkooman@tuxed.net> - 0.4.0-1
- update to 0.4.0

* Sun Apr 12 2015 François Kooman <fkooman@tuxed.net> - 0.3.10-1
- update to 0.3.10

* Fri Apr 10 2015 François Kooman <fkooman@tuxed.net> - 0.3.9-1
- update to 0.3.9

* Tue Apr 07 2015 François Kooman <fkooman@tuxed.net> - 0.3.8-1
- update to 0.3.8

* Sat Mar 28 2015 François Kooman <fkooman@tuxed.net> - 0.3.7-1
- update to 0.3.7

* Fri Mar 27 2015 François Kooman <fkooman@tuxed.net> - 0.3.6-1
- update to 0.3.6

* Fri Mar 27 2015 François Kooman <fkooman@tuxed.net> - 0.3.5-1
- update to 0.3.5

* Tue Mar 24 2015 François Kooman <fkooman@tuxed.net> - 0.3.4-1
- update to 0.3.4

* Mon Mar 23 2015 François Kooman <fkooman@tuxed.net> - 0.3.3-1
- update to 0.3.3

* Thu Mar 19 2015 François Kooman <fkooman@tuxed.net> - 0.3.2-1
- update to 0.3.2

* Tue Mar 17 2015 François Kooman <fkooman@tuxed.net> - 0.3.1-1
- update to 0.3.1

* Mon Mar 16 2015 François Kooman <fkooman@tuxed.net> - 0.3.0-1
- update to 0.3.0

* Sun Mar 15 2015 François Kooman <fkooman@tuxed.net> - 0.2.9-1
- update to 0.2.9

* Sun Mar 15 2015 François Kooman <fkooman@tuxed.net> - 0.2.8-1
- update to 0.2.8

* Wed Mar 11 2015 François Kooman <fkooman@tuxed.net> - 0.2.7-1
- update to 0.2.7

* Tue Mar 10 2015 François Kooman <fkooman@tuxed.net> - 0.2.6-1
- update to 0.2.6

* Tue Mar 10 2015 François Kooman <fkooman@tuxed.net> - 0.2.5-1
- update to 0.2.5

* Thu Mar 05 2015 François Kooman <fkooman@tuxed.net> - 0.2.4-1
- update to 0.2.4

* Wed Mar 04 2015 François Kooman <fkooman@tuxed.net> - 0.2.3-1
- update to 0.2.3

* Mon Mar 02 2015 François Kooman <fkooman@tuxed.net> - 0.2.2-1
- update to 0.2.2

* Thu Feb 26 2015 François Kooman <fkooman@tuxed.net> - 0.2.1-1
- update to 0.2.1

* Tue Feb 24 2015 François Kooman <fkooman@tuxed.net> - 0.2.0-1
- update to 0.2.0
- require PHP >= 5.4

* Tue Feb 24 2015 François Kooman <fkooman@tuxed.net> - 0.1.10-1
- update to 0.1.10

* Mon Feb 23 2015 François Kooman <fkooman@tuxed.net> - 0.1.9-1
- update to 0.1.9

* Mon Feb 23 2015 François Kooman <fkooman@tuxed.net> - 0.1.8-1
- update to 0.1.8

* Sun Feb 22 2015 François Kooman <fkooman@tuxed.net> - 0.1.7-1
- update to 0.1.7

* Sat Feb 21 2015 François Kooman <fkooman@tuxed.net> - 0.1.6-1
- update to 0.1.6

* Sat Feb 21 2015 François Kooman <fkooman@tuxed.net> - 0.1.5-1
- update to 0.1.5

* Sat Feb 21 2015 François Kooman <fkooman@tuxed.net> - 0.1.4-1
- update to 0.1.4

* Fri Feb 20 2015 François Kooman <fkooman@tuxed.net> - 0.1.3-1
- update to 0.1.3

* Wed Feb 18 2015 François Kooman <fkooman@tuxed.net> - 0.1.2-1
- update to 0.1.2

* Tue Feb 17 2015 François Kooman <fkooman@tuxed.net> - 0.1.1-1
- update to 0.1.1

* Sat Jan 31 2015 François Kooman <fkooman@tuxed.net> - 0.1.0-1
- initial package
