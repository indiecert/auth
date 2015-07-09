# Changes

## 0.5.7
- fetch validating certificate on home page to not work when redirecting
  to HTTP URLs

## 0.5.6
- update `guzzlehttp/guzzle`

## 0.5.5
- cleanup indexPage by removing commented out HTML
- remove label from sign in box, was never properly aligned anyway...

## 0.5.4
- fix autoloader when using RPM package

## 0.5.3
- update and fix dependencies

## 0.5.2
- fix backtrace when the selected certificate was not found on the homepage

## 0.5.1
- update `phpseclib/phpseclib` to 2.0 dev branch, to benefit from PSR-4
- allow to specify SAN in the generated client certificate

## 0.5.0
- major new release, rebase on new `fkooman/rest`
- set the default background to white, it seems Firefox on Fedora 22 has grey
  background by default?
- implement introspection endpoint instead of overloading the token endpoint
  for verification by resource servers, e.g. micropub

## 0.4.8
- use `rel="publickey"` now instead of `rel="me"` for fingerprint, `rel="me"`
  is still supported for now, but `faq` and `missingFingerprint` templates
  updated to say `rel="publickey"` (issue #17)
- update CSS style
- update TemplateManager to support 'global' variables

## 0.4.7
- update `fkooman/rest`
- mention time + timezone in issue/expire dates on account page
- make the website links that open, change the wording a bit on the account
  page
- remove purpose input field for now
- add a little bit of padding to body, looks better on mobile
- mention how to generate certificate fingerprint using openssl commandline, 
  thanks @jansauer
- no longer mention obsolete blog post in FAQ

## 0.4.6
- use APCu (if available) to cache fetching the user's homepage instead of 
  downloading it twice: once on authentication and once on confirm. Initial
  caching strategy
- update Dockerfile
- update HTML example in `missingFingerprint` template

## 0.4.5
- use CSRF protection built in `fkooman/rest` which makes the protection
  more uniform
- update `fkooman/rest-plugin-indieauth`
- use POST for logout now instead of GET to accomodate updated 
  `fkooman/rest-plugin-indieauth`

## 0.4.4
- move `/authenticate` to `/login`, mention which URL the user tried to
  access on the login dialog

## 0.4.3
- update `fkooman/rest-plugin-indieauth` to support redirecting in case
  of unauthenticated requests to protected endpoints

## 0.4.2
- separate token validation class and add initial unit test
- update `fkooman/rest` to support 'default disabled' plugins cleaning up to
  code a lot
- implement generation of authentication tokens needed for token validation
  by micropub endpoint
- remove all `<blockquote>`'s
- make it possible to manually delete granted access tokens on the account 
  page
- use `fkooman/rest-plugin-bearer` for token validation on `token` endpoint
  instead of rolling our own
- implement token introspection according to 
  `draft-ietf-oauth-introspection-08`

## 0.4.1
- introduce 'account' page instead of 'success' page
- show granted approvals and access tokens on the user's account page
- rework some CSS
- add more unit tests
- get rid of the `/welcome` page, no longer needed

## 0.4.0
- fix typo in confirmation screen
- do not show misleading `redirect_uri` errors when the error is actually
  in the `client_id` (issue #12)
- implement `scope`/`access_token` support (useful for micropub integration)
- **BREAKING** database layout changed
- fix a security issue where the `confirm` page did not require a valid
  client certificate, allowing any attacker to register approvals for any
  one. It did **NOT** allow impersonation of other users
- add some initial unit tests

## 0.3.10
- update `fkooman/rest` and `fkooman/rest-plugin-indieauth`

## 0.3.9
- use normalize.css to get consistency between browsers and style form elements
- style the form buttons and the "try me" form a little to look better
- update FAQ

## 0.3.8
- update supported browser list on enroll page
- remove the reject button from confirm screen, not approving is
  reject enough
- change position of checkbox

## 0.3.7
- increase font size of code blocks
- fix minor JSON formatting issue in RP page
- fix blockquotes in templates
- validate that `client_id` host matches `redirect_uri` host
- show `client_id` instead of `redirect_uri` host in confirmation dialog
- update the askConfirmation dialog

## 0.3.6
- Implement Twig template caching
- Use separate footer and header template include

## 0.3.5
- include `indiecert-housekeeping` script to remove expired approvals
  where the user never came back and codes that were never claimed
- remove `PageResponse` class, no need anymore 
- some refactoring to reduce code duplication
- increase timeout when fetching pages to 10 seconds

## 0.3.4
- update `fkooman/rest`
- update `fkooman/rest-plugin-indieauth`

## 0.3.3
- update FAQ and welcome page text

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
