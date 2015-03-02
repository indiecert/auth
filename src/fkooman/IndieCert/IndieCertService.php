<?php

/**
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace fkooman\IndieCert;

use fkooman\Http\Request;
use fkooman\Http\Response;
use fkooman\Http\JsonResponse;
use fkooman\Rest\Service;
use GuzzleHttp\Client;
use fkooman\X509\CertParser;
use fkooman\X509\CertParserException;
use fkooman\Http\Uri;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\UriException;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\Exception\ForbiddenException;
use DomDocument;

class IndieCertService extends Service
{
    /** @var string */
    private $caCrt;

    /** @var string */
    private $caKey;

    /** @var fkooman\RelMeAuth\PdoStorage */
    private $pdoStorage;

    /** @var GuzzleHttp\Client */
    private $client;

    /** @var fkooman\IndieCert\IO */
    private $io;

    /** @var fkooman\IndieCert\TemplateManager */
    private $templateManager;

    public function __construct($caCrt, $caKey, PdoStorage $pdoStorage, Client $client = null, IO $io = null)
    {
        parent::__construct();

        $this->caCrt = $caCrt;
        $this->caKey = $caKey;
        $this->pdoStorage = $pdoStorage;

        if (null === $client) {
            $client = new Client();
        }
        $this->client = $client;
   
        if (null === $io) {
            $io = new IO();
        }
        $this->io = $io;

        $this->templateManager = new TemplateManager();

        $this->setDefaultRoute('/welcome');

        $this->get(
            '/faq',
            function (Request $request) {
                return $this->getFaq($request);
            }
        );

        $this->get(
            '/welcome',
            function (Request $request) {
                return $this->getWelcome($request);
            }
        );

        $this->get(
            '/rp',
            function (Request $request) {
                return $this->getRp($request);
            }
        );

        $this->get(
            '/cb',
            function (Request $request) {
                return $this->getCb($request);
            }
        );

        $this->get(
            '/auth',
            function (Request $request) {
                return $this->getAuth($request);
            }
        );

        $this->post(
            '/auth',
            function (Request $request) {
                return $this->postAuth($request);
            }
        );

        $this->post(
            '/verify',
            function (Request $request) {
                return $this->postVerify($request);
            }
        );

        $this->get(
            '/enroll',
            function (Request $request) {
                return $this->getEnroll($request);
            }
        );

        $this->post(
            '/enroll',
            function (Request $request) {
                return $this->postEnroll($request);
            }
        );
    }

    public function getFaq(Request $request)
    {
        return $this->templateManager->render('faqPage');
    }

    public function getWelcome(Request $request)
    {
        $redirectUri = $request->getRequestUri()->getBaseUri() . $request->getAppRoot() . 'cb';
        return $this->templateManager->render(
            'welcomePage',
            array(
                'redirect_uri' => $redirectUri
            )
        );
    }

    public function getRp(Request $request)
    {
        $authUri = $request->getRequestUri()->getBaseUri() . $request->getAppRoot() . 'auth';
        $verifyPath = $request->getAppRoot() . 'verify';
        $hostName = $request->getRequestUri()->getHost();
        return $this->templateManager->render(
            'relyingPartyPage',
            array(
                'authUri' => $authUri,
                'verifyPath' => $verifyPath,
                'hostName' => $hostName
            )
        );
    }

    public function getCb(Request $request)
    {
        // this is the callback from the 'try it'
        $appRootUri = $request->getRequestUri()->getBaseUri() . $request->getAppRoot();
        $redirectUri = $appRootUri . 'cb';
        $verifyUri = $appRootUri . 'verify';

        if (0 !== strpos($request->getHeader('HTTP_REFERER'), $appRootUri)) {
            throw new BadRequestException('CSRF protection on callback triggered');
        }

        $code = $this->validateCode($request->getQueryParameter('code'));
                
        $verifyRequest = $this->client->createRequest(
            'POST',
            $verifyUri,
            array(
                'body' => array(
                    'code' => $code,
                    'redirect_uri' => $redirectUri
                )
            )
        );
        $verifyResponse = $this->client->send($verifyRequest)->json();
        $me = $verifyResponse['me'];

        return $this->templateManager->render(
            'authenticatedPage',
            array(
                'me' => $me
            )
        );
    }

    public function getEnroll(Request $request)
    {
        return $this->templateManager->render(
            'enrollPage',
            array(
                'certChallenge' => $this->io->getRandomHex(),
                'referrer' => $request->getHeader('HTTP_REFERER')
            )
        );
    }

    public function postEnroll(Request $request)
    {
        $spkac = $request->getPostParameter('spkac');

        // FIXME: validate the key size
        // FIXME: validate the challenge

        $userAgent = $request->getHeader('USER_AGENT');
        if (false !== strpos($userAgent, 'Chrome')) {
            // Chrom(e)(ium) needs the certificate format to be DER
            $format = CertManager::FORMAT_DER;
        } else {
            $format = CertManager::FORMAT_PEM;
        }

        // determine serialNumber
        $commonName = $this->io->getRandomHex();

        // we want to keep a list of CN/serial for book keeping and revocation
        
        $certManager = new CertManager($this->pdoStorage, $this->caCrt, $this->caKey);
        $clientCert = $certManager->generateClientCertificate($spkac, $commonName, $format);

        $response = new Response(200, 'application/x-x509-user-cert');
        $response->setContent($clientCert);

        return $response;
    }

    public function getAuth(Request $request)
    {
        $me = $this->validateMe($request->getQueryParameter('me'));
        $redirectUri = $this->validateRedirectUri($request->getQueryParameter('redirect_uri'));
        $state = $this->validateState($request->getQueryParameter('state'));

        $certFingerprint = $this->getCertFingerprint($request->getHeader('SSL_CLIENT_CERT'));
        if (false === $certFingerprint) {
            return $this->templateManager->render('noCert');
        }

        $pageFetcher = new PageFetcher($this->client);
        $pageResponse = $pageFetcher->fetch($me);

        $relMeLinks = $this->extractRelMeLinks($pageResponse->getBody());

        if (false === $this->hasFingerprint($relMeLinks, $certFingerprint)) {
            return $this->templateManager->render(
                'missingFingerprint',
                array(
                    'me' => $pageResponse->getEffectiveUrl(),
                    'certFingerprint' => $certFingerprint
                )
            );
        }

        $approval = $this->pdoStorage->getApproval($pageResponse->getEffectiveUrl(), $redirectUri);
        if (false !== $approval) {
            // check if not expired
            if ($this->io->getTime() >= $approval['expires_at']) {
                $this->pdoStorage->deleteApproval($pageResponse->getEffectiveUrl(), $redirectUri);
                $approval = false;
            }
        }
    
        if (false === $approval) {
            $redirectUriObj = new Uri($redirectUri);

            return $this->templateManager->render(
                'askConfirmation',
                array(
                    'me' => $pageResponse->getEffectiveUrl(),
                    'host' => $redirectUriObj->getHost()
                )
            );
        }

        // create indiecode
        $code = $this->io->getRandomHex();
        $this->pdoStorage->storeIndieCode(
            $code,
            $pageResponse->getEffectiveUrl(),
            $redirectUri,
            $this->io->getTime()
        );

        if (null === $state) {
            $responseUri = sprintf('%s?code=%s', $redirectUri, $code);
        } else {
            $responseUri = sprintf('%s?code=%s&state=%s', $redirectUri, $code, $state);
        }

        return new RedirectResponse($responseUri, 302);
    }

    public function postAuth(Request $request)
    {
        $me = $this->validateMe($request->getQueryParameter('me'));
        $redirectUri = $this->validateRedirectUri($request->getQueryParameter('redirect_uri'));
        $state = $this->validateState($request->getQueryParameter('state'));

        // CSRF protection
        if ($request->getHeader('HTTP_REFERER') !== $request->getRequestUri()->getUri()) {
            throw new BadRequestException('CSRF protection triggered');
        }
        
        if ('approve' !== $request->getPostParameter('approval')) {
            throw new ForbiddenException('user did not approve identity validation');
        }

        $certFingerprint = $this->getCertFingerprint($request->getHeader('SSL_CLIENT_CERT'));
        if (false === $certFingerprint) {
            return $this->templateManager->render('noCert');
        }

        $pageFetcher = new PageFetcher($this->client);
        $pageResponse = $pageFetcher->fetch($me);

        $relMeLinks = $this->extractRelMeLinks($pageResponse->getBody());

        if (false === $this->hasFingerprint($relMeLinks, $certFingerprint)) {
            return $this->templateManager->render(
                'missingFingerprint',
                array(
                    'me' => $pageResponse->getEffectiveUrl(),
                    'certFingerprint' => $certFingerprint
                )
            );
        }

        // remember
        if (null !== $request->getPostParameter('remember')) {
            $this->pdoStorage->storeApproval($pageResponse->getEffectiveUrl(), $redirectUri, $this->io->getTime() + 3600*24*7);
        }

        // create indiecode
        $code = $this->io->getRandomHex();
        $this->pdoStorage->storeIndieCode(
            $code,
            $pageResponse->getEffectiveUrl(),
            $redirectUri,
            $this->io->getTime()
        );

        if (null === $state) {
            $responseUri = sprintf('%s?code=%s', $redirectUri, $code);
        } else {
            $responseUri = sprintf('%s?code=%s&state=%s', $redirectUri, $code, $state);
        }

        return new RedirectResponse($responseUri, 302);
    }

    public function postVerify(Request $request)
    {
        $code = $this->validateCode($request->getPostParameter('code'));
        if (null === $code) {
            throw new BadRequestException('missing code');
        }
        $redirectUri = $this->validateRedirectUri($request->getPostParameter('redirect_uri'));

        $indieCode = $this->pdoStorage->getIndieCode($code, $redirectUri);

        if (false === $indieCode) {
            //throw new BadRequestException('invalid_request');
            $response = new JsonResponse(400);
            $response->setContent(
                array(
                    'error' => 'invalid_request'
                )
            );

            return $response;
        }

        if ($this->io->getTime() > $indieCode['issue_time'] + 600) {
            // FIXME: this MUST be JSON response!
            throw new BadRequestException('code expired');
        }

        $response = new JsonResponse();
        $response->setContent(
            array(
                'me' => $indieCode['me']
            )
        );

        return $response;
    }

    private function hasFingerprint(array $relMeLinks, $certFingerprint)
    {
        $certFingerprints = array();
        foreach ($relMeLinks as $meLink) {
            if (preg_match('/^di:sha-256;[a-zA-Z0-9_-]+\?ct=application\/x-x509-user-cert$/', $meLink)) {
                $certFingerprints[] = $meLink;
            }
        }

        if (!in_array($certFingerprint, $certFingerprints)) {
            return false;
        }

        return true;
    }

    private function getCertFingerprint($clientCert)
    {
        // determine certificate fingerprint
        try {
            $certParser = new CertParser($clientCert);
            return sprintf(
                'di:sha-256;%s?ct=application/x-x509-user-cert',
                $certParser->getFingerPrint('sha256', true)
            );
        } catch (CertParserException $e) {
            return false;
        }
    }

    private function extractRelMeLinks($htmlString)
    {
        $dom = new DomDocument();
        // disable error handling by DomDocument so we handle them ourselves
        libxml_use_internal_errors(true);
        $dom->loadHTML($htmlString);
        // throw away all errors, we do not care about them anyway
        libxml_clear_errors();

        $tags = array('link', 'a');
        $relMeLinks = array();
        foreach ($tags as $tag) {
            $elements = $dom->getElementsByTagName($tag);
            foreach ($elements as $element) {
                $href = $element->getAttribute('href');
                $rel = $element->getAttribute('rel');
                if ('me' === $rel) {
                    $relMeLinks[] = $href;
                }
            }
        }

        return $relMeLinks;
    }

    private function validateMe($me)
    {
        if (null === $me) {
            throw new BadRequestException('missing parameter "me"');
        }
        if (0 !== strpos($me, 'http')) {
            $me = sprintf('https://%s', $me);
        }
        try {
            $uriObj = new Uri($me);
            if ('https' !== $uriObj->getScheme()) {
                throw new BadRequestException('"me" must be https uri');
            }
            if (null !== $uriObj->getQuery()) {
                throw new BadRequestException('"me" cannot contain query parameters');
            }
            if (null !== $uriObj->getFragment()) {
                throw new BadRequestException('"me" cannot contain fragment');
            }
            // if we have no path add '/'
            if (null === $uriObj->getPath()) {
                $me .= '/';
            }

            return $me;
        } catch (UriException $e) {
            throw new BadRequestException('"me" is an invalid uri');
        }
    }

    private function validateRedirectUri($redirectUri)
    {
        if (null === $redirectUri) {
            throw new BadRequestException('missing parameter "redirect_uri"');
        }
        try {
            $uriObj = new Uri($redirectUri);
            if ('https' !== $uriObj->getScheme()) {
                throw new BadRequestException('"redirect_uri" must be https uri');
            }
            if (null !== $uriObj->getFragment()) {
                throw new BadRequestException('"redirect_uri" cannot contain fragment');
            }

            return $redirectUri;
        } catch (UriException $e) {
            throw new BadRequestException('"redirect_uri" is an invalid uri');
        }
    }

    private function validateCode($code)
    {
        if (null === $code) {
            throw new BadRequestException('missing parameter "code"');
        }
        if (1 !== preg_match('/^(?:[\x20-\x7E])*$/', $code)) {
            throw new BadRequestException('"code" contains invalid characters');
        }

        return $code;
    }

    public function validateState($state)
    {
        if (null !== $state) {
            if (1 !== preg_match('/^(?:[\x20-\x7E])*$/', $state)) {
                throw new BadRequestException('"state" contains invalid characters');
            }
        }

        return $state;
    }
}
