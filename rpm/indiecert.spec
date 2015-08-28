%global github_owner     fkooman
%global github_name      indiecert

Name:       indiecert
Version:    0.7.0
Release:    1%{?dist}
Summary:    Authentication service using client certificates

Group:      Applications/Internet
License:    AGPLv3+
URL:        https://github.com/%{github_owner}/%{github_name}
Source0:    https://github.com/%{github_owner}/%{github_name}/archive/%{version}.tar.gz
Source1:    indiecert-httpd.conf
Source2:    indiecert-autoload.php

BuildArch:  noarch

Requires:   httpd
Requires:   mod_ssl

Requires:   php(language) >= 5.4
Requires:   php-apc
Requires:   php-dom
Requires:   php-filter
Requires:   php-libxml
Requires:   php-pcre
Requires:   php-pdo
Requires:   php-spl
Requires:   php-standard

Requires:   php-composer(fkooman/ini) >= 1.0.0
Requires:   php-composer(fkooman/ini) < 2.0.0
Requires:   php-composer(fkooman/io) >= 1.0.0
Requires:   php-composer(fkooman/io) < 2.0.0
Requires:   php-composer(fkooman/rest) >= 1.0.1
Requires:   php-composer(fkooman/rest) < 2.0.0
Requires:   php-composer(fkooman/tpl-twig) >= 1.0.0
Requires:   php-composer(fkooman/tpl-twig) < 2.0.0

Requires:   php-composer(fkooman/rest-plugin-authentication-indieauth) >= 1.0.0
Requires:   php-composer(fkooman/rest-plugin-authentication-indieauth) < 2.0.0
Requires:   php-composer(fkooman/rest-plugin-authentication-tls) >= 1.0.0
Requires:   php-composer(fkooman/rest-plugin-authentication-tls) < 2.0.0
Requires:   php-composer(guzzlehttp/guzzle) >= 5.3
Requires:   php-composer(guzzlehttp/guzzle) < 6.0
Requires:   php-composer(phpseclib/phpseclib) >= 2.0.0
Requires:   php-composer(phpseclib/phpseclib) < 3.0.0
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
%doc CHANGES.md README.md composer.json config/
%license agpl-3.0.txt

%changelog
* Fri Aug 28 2015 François Kooman <fkooman@tuxed.net> - 0.7.0-1
- update to 0.7.0

* Mon Aug 10 2015 François Kooman <fkooman@tuxed.net> - 0.6.4-1
- update to 0.6.4

* Thu Jul 30 2015 François Kooman <fkooman@tuxed.net> - 0.6.3-1
- update to 0.6.3
