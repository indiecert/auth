# Changes

## 0.3.2
- update FAQ, relying party documentation and Docker

## 0.3.1
- add `me` to callback parameters after successful authentication

## 0.3.0
- update the FAQ and relying party documentation

## 0.2.9
- update text on various pages
- update `fkooman/rest`
- update `fkooman/rest-plugin-indieauth`
- no longer make IndieCert specific `ni://<domain>/` URIs, just use
  `ni:///`
- use the provided `me` now as the identifier instead of following all
  redirects and using the cannonical URL

## 0.2.8
- update relying party instructions
- change the default httpd config to allow all certificates
- fix HSTS header

## 0.2.7
- change try endpoint to success endpoint
- update FAQ page
- require the `me` field on welcomePage, also change placeholder to 
  `example.org` as the domain is reserved for this exact purpose

## 0.2.6
- show `authorization_endpoint` example on missing fingerprint page
- require `state` parameter in authentication requests
- actually use `fkooman/rest-plugin-indieauth` to implement distributed
  IndieAuth on IndieCert :)

## 0.2.5
- update `fkooman/rest`
- auth endpoint now returns `application/x-www-form-urlencoded` as default
  response type to token verification, override with `Accept` header if you
  want `application/json`
- verify endpoint no longer exists, use "auth" as well for verify endpoint

## 0.2.4
- fix call of getCertFingerprint() to also use hostname
- in case there was no certificate authentication mention that you need a
  certificate issued by IndieCert (issue #2)

## 0.2.3
- update to `ni://` scheme (RFC 6920)

## 0.2.2
- simplify TemplateManager
- fix bug when CSRF protection was triggered when approval was stored with
  'Try Me'

## 0.2.1
- implement state parameter support
- update relying party documentation

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
