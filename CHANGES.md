# Changes

## 0.1.4
- major refactoring

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
