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
use Twig_Loader_Filesystem;
use Twig_Environment;
use Guzzle\Http\Client;
use fkooman\X509\CertParser;
use fkooman\Http\Uri;
use fkooman\Http\Session;
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

    /** @var fkooman\Http\Session */
    private $session;

    /** @var Guzzle\Http\Client */
    private $client;

    public function __construct($caCrt, $caKey, PdoStorage $pdoStorage, Session $session = null, Client $client = null)
    {
        parent::__construct();

        $this->caCrt = $caCrt;
        $this->caKey = $caKey;
        $this->pdoStorage = $pdoStorage;

        if (null === $session) {
            $session = new Session('IndieCert');
        }
        $this->session = $session;

        if (null === $client) {
            $client = new Client();
        }
        $this->client = $client;
   
        // in PHP 5.3 we cannot use $this from a closure
        $compatThis = &$this;

        $this->setDefaultRoute('/welcome');

        $this->get(
            '/welcome',
            function (Request $request) use ($compatThis) {
                return 'Welcome to IndieCert';
            }
        );

        $this->get(
            '/auth',
            function (Request $request) use ($compatThis) {
                return $compatThis->getAuth($request);
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

    public function getEnroll(Request $request)
    {
        $certChallenge = bin2hex(
            openssl_random_pseudo_bytes(8)
        );

        $twig = $this->getTwig();

        return $twig->render(
            'enrollPage.twig',
            array(
                'certChallenge' => $certChallenge,
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
        $commonName = bin2hex(
            openssl_random_pseudo_bytes(16)
        );
        // we want to keep a list of CN/serial for book keeping and revocation
        
        $certManager = new CertManager($this->pdoStorage, $this->caCrt, $this->caKey);
        $clientCert = $certManager->generateClientCertificate($spkac, $commonName, $format);

        $response = new Response(200, 'application/x-x509-user-cert');
        $response->setContent($clientCert);

        return $response;
    }

    public function getAuth(Request $request)
    {
        // first validate the request
        $this->validateQueryParameters($request);

        $me = $request->getQueryParameter('me');
        $clientId = $request->getQueryParameter('client_id');
        $redirectUri = $request->getQueryParameter('redirect_uri');

        $this->session->setValue('me', $me);
        $this->session->setValue('client_id', $clientId);
        $this->session->setValue('redirect_uri', $redirectUri);

        $clientCert = $request->getHeader('SSL_CLIENT_CERT');
        if (null === $clientCert || 0 === strlen($clientCert)) {
            $twig = $this->getTwig();

            return $twig->render(
                'noCert.twig',
                array(
                )
            );
        }

        // determine certificate fingerprint
        $certParser = new CertParser($clientCert);
        $certFingerprint = sprintf(
            'di:sha-256;%s?ct=application/x-x509-user-cert',
            $certParser->getFingerPrint('sha256', true)
        );

        $relMeFetcher = new RelMeFetcher($this->client);
        $relLinks = $relMeFetcher->fetchRel(
            $request->getQueryParameter('me')
        );

        $certFingerprints = array();
        foreach ($relLinks as $meLink) {
            if (preg_match('/^di:sha-256;[a-zA-Z0-9_-]+\?ct=application\/x-x509-user-cert$/', $meLink)) {
                $certFingerprints[] = $meLink;
            }
        }

        if (!in_array($certFingerprint, $certFingerprints)) {
            $twig = $this->getTwig();

            return $twig->render(
                'missingFingerprint.twig',
                array(
                    'me' => $me,
                    'certFingerprint' => $certFingerprint
                )
            );
        }
    
        // create indiecode
        $code = bin2hex(openssl_random_pseudo_bytes(16));
        $this->pdoStorage->storeIndieCode($me, $clientId, $redirectUri, $code);

        // redirect back to app
        return new RedirectResponse(sprintf('%s?code=%s', $redirectUri, $code), 302);
    }

    public function postVerify(Request $request)
    {
        $code = $request->getPostParameter('code');
        if (null === $code) {
            throw new BadRequestException('missing code');
        }
        $clientId = $request->getPostParameter('client_id');
        if (null === $clientId) {
            throw new BadRequestException('missing client_id');
        }
        $redirectUri = $request->getPostParameter('redirect_uri');
        if (null === $redirectUri) {
            throw new BadRequestException('missing redirect_uri');
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

        if ($clientId !== $indieCode['client_id']) {
            // FIXME: this MUST be JSON response!
            throw new BadRequestException('non matching client_id');
        }
        if ($redirectUri !== $indieCode['redirect_uri']) {
            // FIXME: this MUST be JSON response!
            throw new BadRequestException('non matching redirect_uri');
        }

        $response = new JsonResponse();
        $response->setContent(
            array(
                'me' => $indieCode['me']
            )
        );

        return $response;
    }

    private function validateQueryParameters(Request $request)
    {
        // we must have 'me', 'client_id' and 'redirect_uri' and they all
        // must be valid (HTTPS) URLs and the host of the client_id and
        // redirect_uri must match
        $requiredParameters = array('me', 'client_id', 'redirect_uri');
        foreach ($requiredParameters as $p) {
            $qp = $request->getQueryParameter($p);
            if (null === $qp) {
                throw new BadRequestException(
                    sprintf('missing parameter "%s"', $p)
                );
            }
            try {
                $u = new Uri($qp);
                if ('https' !== $u->getScheme()) {
                    throw new BadRequestException(
                        sprintf('URL must be HTTPS for "%s"', $p)
                    );
                }
            } catch (UriException $e) {
                throw new BadRequestException(
                    sprintf('invalid URL for "%s"', $p)
                );
            }
        }
        $clientId = new Uri($request->getQueryParameter('client_id'));
        $redirectUri = new Uri($request->getQueryParameter('redirect_uri'));
        if ($clientId->getHost() !== $redirectUri->getHost()) {
            throw new BadRequestException(
                'host for client_id and redirect_uri must match'
            );
        }
    }

    private function getTwig()
    {
        $configTemplateDir = dirname(dirname(dirname(__DIR__))).'/config/views';
        $defaultTemplateDir = dirname(dirname(dirname(__DIR__))).'/views';

        $templateDirs = array();

        // the template directory actually needs to exist, otherwise the
        // Twig_Loader_Filesystem class will throw an exception when loading
        // templates, the actual template does not need to exist though...
        if (false !== is_dir($configTemplateDir)) {
            $templateDirs[] = $configTemplateDir;
        }
        $templateDirs[] = $defaultTemplateDir;

        $loader = new Twig_Loader_Filesystem($templateDirs);
        return new Twig_Environment($loader);
    }
}
