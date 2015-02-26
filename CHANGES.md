# Changes

## 0.2.1
- implement state parameter support

## 0.2.0
- update to Guzzle 4
- require PHP >= 5.4
- remove some PHP 5.3 hacks

## 0.1.10
- substantially update relying party documentation

## 0.1.9
- add RP documentation
- solve CSRF for 'try me' page

## 0.1.8
- updated FAQ
- if `me` does not have a path always add `/`
- update httpd config to only ask for certificate on `/auth`
- use two init scripts for both CA and db instead of only one
- update dependencies
- `me` cannot contain query parameters or fragment
- `redirect_uri` cannot contain fragment

## 0.1.7
- add FAQ
- add Footer
- fix docker instructions to actually work, but needs at least RPM package 
  version 0.1.6 to work properly

## 0.1.6
- make it possible to disable server certificate check for use by the Docker 
  image and local development
- update the templates to remove some old text, make them more colorful and
  update the welcome page substantially

## 0.1.5
- integrate demo in the "welcome" page

## 0.1.4
- major refactoring
- add option to remember approval for a week

## 0.1.3
- expire codes after 10 minutes instead of them being valid indefinitely
  (although they could be used only once)
- use IO class for getting time and random numbers 
- mention browser support so far and Firefox issue in enroll page

## 0.1.2
- implement approval dialog to avoid 'indiejack' attack as demonstrated by 
  `@michielbdejong`
- update text of welcome page a bit and minor style update
- update Docker httpd config

## 0.1.1
- fix CA generation, keySize was not seen as a number apparently
- implement latest protocol from IndieCert blog post 

## 0.1.0
- initial release
