# Changes

## 2.1.6 (2016-06-08)
- fix issue #21 by making a HEAD request always return `200 OK`, 
  handling https://github.com/aaronpk/IndieAuth.com/issues/93

## 2.1.5 (2016-05-25)
- update `fkooman/json`

## 2.1.4 (2016-05-25)
- update `fkooman/io`

## 2.1.3 (2016-01-27)
- another configuration file fix

## 2.1.2 (2016-01-27)
- fix example configuration file

## 2.1.1 (2016-01-27)
- add me parameter to enroll page request

## 2.1.0 (2016-01-27)
- also provide "me" to the enroll script for WebID+TLS identifier by 
  default
- restore the FAQ
- redo CSS
- pull back in enroll in this code, no longer a separate project

## 2.0.1 (2016-01-23)
- allow to specify the enroll URL in the configuration file

## 2.0.0 (2016-01-22)
- major refactor, strip to bare essentials
- rename the init scripts
- update dependencies to latest version
- change configuration format to YAML
- introduce `serverMode` to allow for production or development configuration

## 1.0.1 (2015-09-27)
- rename the bin scripts
- rename the example config file
- update config example to point to correct directories

## 1.0.0 (2015-09-26)
- initial release
