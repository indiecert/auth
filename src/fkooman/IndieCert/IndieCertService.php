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
use Guzzle\Http\Client;
use fkooman\X509\CertParser;
use fkooman\Http\Uri;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\UriException;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\Exception\ForbiddenException;

class IndieCertService extends Service
{
    /** @var string */
    private $caCrt;

    /** @var string */
    private $caKey;

    /** @var fkooman\RelMeAuth\PdoStorage */
    private $pdoStorage;

    /** @var Guzzle\Http\Client */
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

        // in PHP 5.3 we cannot use $this from a closure
        $compatThis = &$this;

        $this->setDefaultRoute('/welcome');

        $this->get(
            '/welcome',
            function (Request $request) use ($compatThis) {
                return $compatThis->getWelcome($request);
            }
        );

        $this->get(
            '/auth',
            function (Request $request) use ($compatThis) {
                return $compatThis->getAuth($request);
            }
        );

        $this->post(
            '/auth',
            function (Request $request) use ($compatThis) {
                return $compatThis->postAuth($request);
            }
        );

        $this->post(
            '/verify',
            function (Request $request) use ($compatThis) {
                return $compatThis->postVerify($request);
            }
        );

        $this->get(
            '/enroll',
            function (Request $request) use ($compatThis) {
                return $compatThis->getEnroll($request);
            }
        );

        $this->post(
            '/enroll',
            function (Request $request) use ($compatThis) {
                return $compatThis->postEnroll($request);
            }
        );
    }

    public function getWelcome(Request $request)
    {
        return $this->templateManager->welcomePage();
    }

    public function getEnroll(Request $request)
    {
        return $this->templateManager->enrollPage(
            $this->io->getRandomHex(),
            $request->getHeader('HTTP_REFERER')
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
        $validatedParameters = $this->validateQueryParameters($request);
        
        $me = $validatedParameters['me'];
        $redirectUri = $validatedParameters['redirect_uri'];
    
        $redirectUriObj = new Uri($redirectUri);

        return $this->templateManager->askConfirmation(
            $me,
            $redirectUriObj->getHost()
        );
    }

    public function postAuth(Request $request)
    {
        // CSRF protection
        if ($request->getHeader('HTTP_REFERER') !== $request->getRequestUri()->getUri()) {
            throw new BadRequestException('CSRF protection triggered');
        }
        $validatedParameters = $this->validateQueryParameters($request);
        
        if ('approve' !== $request->getPostParameter('approval')) {
            throw new ForbiddenException('user did not approve identity validation');
        }

        $me = $validatedParameters['me'];
        $prefixedMe = $validatedParameters['prefixed_me'];
        $redirectUri = $validatedParameters['redirect_uri'];

        $clientCert = $request->getHeader('SSL_CLIENT_CERT');
        if (null === $clientCert || 0 === strlen($clientCert)) {
            return $this->templateManager->noCert();
        }

        // determine certificate fingerprint
        $certParser = new CertParser($clientCert);
        $certFingerprint = sprintf(
            'di:sha-256;%s?ct=application/x-x509-user-cert',
            $certParser->getFingerPrint('sha256', true)
        );

        $relMeFetcher = new RelMeFetcher($this->client);
        $relResponse = $relMeFetcher->fetchRel(
            $prefixedMe
        );

        $certFingerprints = array();
        foreach ($relResponse['relLinks'] as $meLink) {
            if (preg_match('/^di:sha-256;[a-zA-Z0-9_-]+\?ct=application\/x-x509-user-cert$/', $meLink)) {
                $certFingerprints[] = $meLink;
            }
        }

        if (!in_array($certFingerprint, $certFingerprints)) {
            return $this->templateManager->missingFingerprint($relResponse['pageUri'], $certFingerprint);
        }

        // create indiecode
        $code = $this->io->getRandomHex();
        $this->pdoStorage->storeIndieCode($me, $redirectUri, $relResponse['pageUri'], $code, $this->io->getTime());

        return new RedirectResponse(sprintf('%s?me=%s&code=%s', $redirectUri, $me, $code), 302);
    }

    public function postVerify(Request $request)
    {
        $code = $request->getPostParameter('code');
        if (null === $code) {
            throw new BadRequestException('missing code');
        }
        $redirectUri = $request->getPostParameter('redirect_uri');
        if (null === $redirectUri) {
            throw new BadRequestException('missing redirect_uri');
        }
        $me = $request->getPostParameter('me');
        if (null === $me) {
            throw new BadRequestException('missing me');
        }

        $indieCode = $this->pdoStorage->getIndieCode($code);

        if (false === $indieCode) {
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

        if ($redirectUri !== $indieCode['redirect_uri']) {
            // FIXME: this MUST be JSON response!
            throw new BadRequestException('non matching redirect_uri');
        }
        if ($me !== $indieCode['me']) {
            // FIXME: this MUST be JSON response!
            throw new BadRequestException('non matching me');
        }

        $response = new JsonResponse();
        $response->setContent(
            array(
                'me' => $indieCode['normalized_me']
            )
        );

        return $response;
    }

    private function validateQueryParameters(Request $request)
    {
        // we must have 'me' and 'redirect_uri' and they all
        // must be valid (HTTPS) URLs
        $me = $request->getQueryParameter('me');
        $redirectUri = $request->getQueryParameter('redirect_uri');

        if (null === $me || null === $redirectUri) {
            throw new BadRequestException('missing parameter');
        }

        // me is a special case to allow domain logins without prefixing it
        // with 'https://', e.g. 'tuxed.net' will be rewritten as
        // 'https://tuxed.net'
        if (is_string($me) && 0 === strpos($me, 'http')) {
            $prefixedMe = $me;
        } else {
            $prefixedMe = sprintf('https://%s', $me);
        }
   
        try {
            $prefixedMeObj = new Uri($prefixedMe);
            $redirectUriObj = new Uri($redirectUri);
            
            // they all need to have 'https' scheme
            foreach (array($prefixedMeObj, $redirectUriObj) as $u) {
                if ('https' !== $u->getScheme()) {
                    throw new BadRequestException('URL must be HTTPS');
                }
            }
        } catch (UriException $e) {
            throw new BadRequestException('invalid URL in query parameters');
        }

        return array(
            'me' => $me,
            'prefixed_me' => $prefixedMe,
            'redirect_uri' => $redirectUri
        );
    }
}
