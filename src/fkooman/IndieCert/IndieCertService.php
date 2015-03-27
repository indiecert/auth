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
use fkooman\Http\FormResponse;
use fkooman\Rest\Service;
use GuzzleHttp\Client;
use fkooman\X509\CertParser;
use fkooman\X509\CertParserException;
use fkooman\Http\Uri;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\Exception\ForbiddenException;
use DomDocument;
use fkooman\Rest\Plugin\UserInfo;
use InvalidArgumentException;

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

    public function __construct($caCrt, $caKey, PdoStorage $pdoStorage, Client $client = null, IO $io = null, TemplateManager $templateManager = null)
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
    
        if (null === $templateManager) {
            $templateManager = new TemplateManager();
        }
        $this->templateManager = $templateManager;

        $this->setDefaultRoute('/welcome');

        $this->get(
            '/faq',
            function (Request $request) {
                return $this->getFaq($request);
            },
            array('skipPlugins' => array('fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'))
        );

        $this->get(
            '/welcome',
            function (Request $request) {
                return $this->getWelcome($request);
            },
            array('skipPlugins' => array('fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'))
        );

        $this->get(
            '/rp',
            function (Request $request) {
                return $this->getRp($request);
            },
            array('skipPlugins' => array('fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'))
        );

        // for this URL you actually need to be authenticated...
        $this->get(
            '/success',
            function (Request $request, UserInfo $userInfo) {
                return $this->getSuccess($request, $userInfo);
            }
        );

        $this->get(
            '/auth',
            function (Request $request) {
                return $this->getAuth($request);
            },
            array('skipPlugins' => array('fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'))
        );

        $this->post(
            '/confirm',
            function (Request $request) {
                return $this->postConfirm($request);
            },
            array('skipPlugins' => array('fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'))
        );

        $this->post(
            '/auth',
            function (Request $request) {
                return $this->postAuth($request);
            },
            array('skipPlugins' => array('fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'))
        );

        $this->get(
            '/enroll',
            function (Request $request) {
                return $this->getEnroll($request);
            },
            array('skipPlugins' => array('fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'))
        );

        $this->post(
            '/enroll',
            function (Request $request) {
                return $this->postEnroll($request);
            },
            array('skipPlugins' => array('fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'))
        );
    }

    public function getFaq(Request $request)
    {
        return $this->templateManager->render('faqPage');
    }

    public function getWelcome(Request $request)
    {
        $redirectUri = $request->getAbsRoot() . 'cb';
        return $this->templateManager->render(
            'welcomePage',
            array(
                'redirect_uri' => $redirectUri
            )
        );
    }

    public function getRp(Request $request)
    {
        $authUri = $request->getAbsRoot() . 'auth';
        $verifyPath = $request->getRoot() . 'auth';
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

    public function getSuccess(Request $request, UserInfo $userInfo)
    {
        return $this->templateManager->render(
            'authenticatedPage',
            array(
                'me' => $userInfo->getUserId()
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
        $clientId = $this->validateUri($request->getQueryParameter('client_id'));
        $redirectUri = $this->validateUri($request->getQueryParameter('redirect_uri'));
        $state = $this->validateState($request->getQueryParameter('state'));

        $clientIdUriObj = new Uri($clientId);
        $redirectUriObj = new Uri($redirectUri);

        if ($clientIdUriObj->getHost() !== $redirectUriObj->getHost()) {
            throw new BadRequestException('client_id must have same host as redirect_uri');
        }

        $certFingerprint = $this->getCertFingerprint(
            $request->getHeader('SSL_CLIENT_CERT')
        );

        if (false === $certFingerprint) {
            return $this->templateManager->render('noCert');
        }

        $pageFetcher = new PageFetcher($this->client);
        $htmlResponse = $pageFetcher->fetch($me);
        $relMeLinks = $this->extractRelMeLinks($htmlResponse);

        $authorizationEndpoint = $request->getAbsRoot() . 'auth';

        if (false === $this->hasFingerprint($relMeLinks, $certFingerprint)) {
            return $this->templateManager->render(
                'missingFingerprint',
                array(
                    'me' => $me,
                    'certFingerprint' => $certFingerprint,
                    'authorizationEndpoint' => $authorizationEndpoint
                )
            );
        }

        $approval = $this->pdoStorage->getApproval($me, $redirectUri);
        if (false !== $approval) {
            // check if not expired
            if ($this->io->getTime() >= $approval['expires_at']) {
                $this->pdoStorage->deleteApproval($me, $redirectUri);
                $approval = false;
            }
        }
    
        if (false === $approval) {
            $confirmUri = sprintf(
                'confirm?redirect_uri=%s&me=%s&state=%s',
                $redirectUri,
                $me,
                $state
            );

            return $this->templateManager->render(
                'askConfirmation',
                array(
                    'confirmUri' => $confirmUri,
                    'me' => $me,
                    'clientId' => $clientId,
                    'redirectUri' => $redirectUri
                )
            );
        }

        return $this->indieCodeRedirect($me, $redirectUri, $state);
    }

    public function postConfirm(Request $request)
    {
        $me = $this->validateMe($request->getQueryParameter('me'));
        $redirectUri = $this->validateUri($request->getQueryParameter('redirect_uri'));
        $state = $this->validateState($request->getQueryParameter('state'));
        $appRootUri = $request->getAbsRoot();

        // CSRF protection
        if (0 !== strpos($request->getHeader('HTTP_REFERER'), $appRootUri . 'auth')) {
            throw new BadRequestException('CSRF protection triggered');
        }
        
        if ('approve' !== $request->getPostParameter('approval')) {
            throw new ForbiddenException('user did not approve identity validation');
        }

        // because of the referrer check we know the browser came from the
        // 'auth' URI and that certificate was already checked before...

        // store approval if requested
        if (null !== $request->getPostParameter('remember')) {
            $this->pdoStorage->storeApproval($me, $redirectUri, $this->io->getTime() + 3600*24*7);
        }

        return $this->indieCodeRedirect($me, $redirectUri, $state);
    }

    public function postAuth(Request $request)
    {
        $code = $this->validateCode($request->getPostParameter('code'));
        if (null === $code) {
            throw new BadRequestException('missing code');
        }
        $redirectUri = $this->validateUri($request->getPostParameter('redirect_uri'));

        $indieCode = $this->pdoStorage->getIndieCode($code, $redirectUri);

        if (false === $indieCode) {
            throw new BadRequestException('invalid_request', 'code not found');
        }

        if ($this->io->getTime() > $indieCode['issue_time'] + 600) {
            throw new BadRequestException('invalid_request', 'code expired');
        }
    
        // default to "application/x-www-form-urlencoded" for now...
        if (false !== strpos($request->getHeader('Accept'), 'application/json')) {
            $response = new JsonResponse();
        } else {
            $response = new FormResponse();
        }
        $response->setContent(
            array(
                'me' => $indieCode['me']
            )
        );

        return $response;
    }

    public function indieCodeRedirect($me, $redirectUri, $state)
    {
        // create indiecode
        $code = $this->io->getRandomHex();
        $this->pdoStorage->storeIndieCode(
            $code,
            $me,
            $redirectUri,
            $this->io->getTime()
        );

        $responseUri = sprintf('%s?me=%s&code=%s&state=%s', $redirectUri, $me, $code, $state);

        return new RedirectResponse($responseUri, 302);
    }

    private function hasFingerprint(array $relMeLinks, $certFingerprint)
    {
        $certFingerprints = array();

        $pattern = '/^ni:\/\/\/sha-256;[a-zA-Z0-9_-]+\?ct=application\/x-x509-user-cert$/';

        foreach ($relMeLinks as $meLink) {
            if (1 === preg_match($pattern, $meLink)) {
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
                'ni:///sha-256;%s?ct=application/x-x509-user-cert',
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
        if (0 !== stripos($me, 'http')) {
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

            return $uriObj->getUri();
        } catch (InvalidArgumentException $e) {
            throw new BadRequestException('"me" is an invalid uri');
        }
    }

    private function validateUri($redirectUri)
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

            return $uriObj->getUri();
        } catch (InvalidArgumentException $e) {
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

    private function validateState($state)
    {
        if (null === $state) {
            throw new BadRequestException('missing parameter "state"');
        }
        if (1 !== preg_match('/^(?:[\x20-\x7E])*$/', $state)) {
            throw new BadRequestException('"state" contains invalid characters');
        }

        return $state;
    }
}
