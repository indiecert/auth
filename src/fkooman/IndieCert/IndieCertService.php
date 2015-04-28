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
use fkooman\Http\Uri;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\Exception\ForbiddenException;
use fkooman\Http\Exception\UnauthorizedException;
use fkooman\Rest\Plugin\UserInfo;
use InvalidArgumentException;

class IndieCertService extends Service
{
    /** @var fkooman\RelMeAuth\PdoStorage */
    private $db;

    /** @var fkooman\IndieCert\CertManager */
    private $certManager;

    /** @var GuzzleHttp\Client */
    private $client;

    /** @var fkooman\IndieCert\TemplateManager */
    private $templateManager;

    /** @var fkooman\IndieCert\IO */
    private $io;

    public function __construct(PdoStorage $db, CertManager $certManager, Client $client = null, TemplateManager $templateManager = null, IO $io = null)
    {
        parent::__construct();

        $this->db = $db;
        $this->certManager = $certManager;

        // Guzzle
        if (null === $client) {
            $client = new Client();
        }
        $this->client = $client;
   
        // IO
        if (null === $io) {
            $io = new IO();
        }
        $this->io = $io;
        
        // TemplateManager
        if (null === $templateManager) {
            $templateManager = new TemplateManager();
        }
        $this->templateManager = $templateManager;

        // Autentication NOT needed
        $this->get(
            '/',
            function (Request $request) {
                return $this->getIndex($request);
            }
        );

        $this->get(
            '/faq',
            function (Request $request) {
                return $this->getFaq($request);
            }
        );

        $this->get(
            '/rp',
            function (Request $request) {
                return $this->getRp($request);
            }
        );

        $this->get(
            '/auth',
            function (Request $request) {
                return $this->getAuth($request);
            }
        );

        $this->post(
            '/confirm',
            function (Request $request) {
                return $this->postConfirm($request);
            }
        );

        $this->post(
            '/auth',
            function (Request $request) {
                return $this->postAuth($request);
            }
        );

        $this->get(
            '/token',
            function (Request $request, IndieTokenInfo $indieTokenInfo) {
                return $this->getToken($request, $indieTokenInfo);
            },
            array(
                'enablePlugins' => array(
                    'fkooman\IndieCert\IndieTokenAuthentication'
                )
            )
        );
    
        $this->post(
            '/token',
            function (Request $request) {
                return $this->postToken($request);
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

        // MUST be authenticated
        $this->get(
            '/account',
            function (Request $request, UserInfo $userInfo) {
                return $this->getAccount($request, $userInfo);
            },
            array(
                'enablePlugins' => array(
                    'fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'
                )
            )
        );
    }

    private function getIndex(Request $request)
    {
        $redirectUri = $request->getAbsRoot() . 'cb';
        return $this->templateManager->render(
            'indexPage',
            array(
                'redirect_uri' => $redirectUri,
            )
        );
    }

    private function getFaq(Request $request)
    {
        return $this->templateManager->render(
            'faqPage'
        );
    }

    private function getRp(Request $request)
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

    private function getEnroll(Request $request)
    {
        return $this->templateManager->render(
            'enrollPage',
            array(
                'certChallenge' => $this->io->getRandomHex(),
                'referrer' => $request->getHeader('HTTP_REFERER')
            )
        );
    }

    private function postEnroll(Request $request)
    {
        $userCert = $this->certManager->enroll(
            $request->getPostParameter('spkac'),
            $request->getHeader('USER_AGENT')
        );

        $response = new Response(200, 'application/x-x509-user-cert');
        $response->setContent($userCert);

        return $response;
    }

    private function getAuth(Request $request)
    {
        $me = InputValidation::validateMe($request->getQueryParameter('me'));
        $clientId = InputValidation::validateUri($request->getQueryParameter('client_id'), 'client_id');
        $redirectUri = InputValidation::validateUri($request->getQueryParameter('redirect_uri'), 'redirect_uri');
        $scope = InputValidation::validateScope($request->getQueryParameter('scope'));
        $state = InputValidation::validateState($request->getQueryParameter('state'));
        
        $clientIdUriObj = new Uri($clientId);
        $redirectUriObj = new Uri($redirectUri);

        if ($clientIdUriObj->getHost() !== $redirectUriObj->getHost()) {
            throw new BadRequestException('client_id must have same host as redirect_uri');
        }
    
        // FIXME: code duplication in the postConfirm method
        $fingerprintData = $request->getHeader('SSL_CLIENT_CERT');
        if (empty($fingerprintData)) {
            return $this->templateManager->render('noCert');
        }
        $certificateValidator = new CertificateValidator(
            $fingerprintData,
            $this->client
        );

        if (false === $certificateValidator->hasFingerprint($me)) {
            $authorizationEndpoint = $request->getAbsRoot() . 'auth';

            return $this->templateManager->render(
                'missingFingerprint',
                array(
                    'me' => $me,
                    'certFingerprint' => $certificateValidator->getFingerprint(),
                    'authorizationEndpoint' => $authorizationEndpoint
                )
            );
        }

        $approval = $this->db->getApproval($me, $clientId, $redirectUri, $scope);
        if (false !== $approval) {
            // check if not expired
            if ($this->io->getTime() >= $approval['expires_at']) {
                $this->db->deleteApproval($me, $clientId, $redirectUri, $scope);
                $approval = false;
            }
        }
    
        if (false === $approval) {
            if (null === $scope) {
                $confirmUri = sprintf(
                    'confirm?client_id=%s&redirect_uri=%s&me=%s&state=%s',
                    $clientId,
                    $redirectUri,
                    $me,
                    $state
                );
            } else {
                $confirmUri = sprintf(
                    'confirm?client_id=%s&redirect_uri=%s&me=%s&scope=%s&state=%s',
                    $clientId,
                    $redirectUri,
                    $me,
                    $scope,
                    $state
                );
            }

            return $this->templateManager->render(
                'askConfirmation',
                array(
                    'confirmUri' => $confirmUri,
                    'me' => $me,
                    'clientId' => $clientId,
                    'redirectUri' => $redirectUri,
                    'scope' => $scope
                )
            );
        }

        return $this->indieCodeRedirect($me, $clientId, $redirectUri, $scope, $state);
    }

    private function postConfirm(Request $request)
    {
        $me = InputValidation::validateMe($request->getQueryParameter('me'));
        $clientId = InputValidation::validateUri($request->getQueryParameter('client_id'), 'client_id');
        $redirectUri = InputValidation::validateUri($request->getQueryParameter('redirect_uri'), 'redirect_uri');
        $scope = InputValidation::validateScope($request->getQueryParameter('scope'));
        $state = InputValidation::validateState($request->getQueryParameter('state'));
        $appRootUri = $request->getAbsRoot();

        // CSRF protection
        if (0 !== strpos($request->getHeader('HTTP_REFERER'), $appRootUri . 'auth')) {
            throw new BadRequestException('CSRF protection triggered');
        }

        $fingerprintData = $request->getHeader('SSL_CLIENT_CERT');
        if (empty($fingerprintData)) {
            return $this->templateManager->render('noCert');
        }
        $certificateValidator = new CertificateValidator(
            $fingerprintData,
            $this->client
        );

        if (false === $certificateValidator->hasFingerprint($me)) {
            $authorizationEndpoint = $request->getAbsRoot() . 'auth';

            return $this->templateManager->render(
                'missingFingerprint',
                array(
                    'me' => $me,
                    'certFingerprint' => $certificateValidator->getFingerprint(),
                    'authorizationEndpoint' => $authorizationEndpoint
                )
            );
        }

        // store approval if requested
        if (null !== $request->getPostParameter('remember')) {
            $this->db->storeApproval($me, $clientId, $redirectUri, $scope, $this->io->getTime() + 3600*24*7);
        }

        return $this->indieCodeRedirect($me, $clientId, $redirectUri, $scope, $state);
    }

    private function postAuth(Request $request)
    {
        return $this->postAuthToken($request, 'used_for_auth');
    }

    private function postToken(Request $request)
    {
        return $this->postAuthToken($request, 'used_for_token');
    }
    
    private function postAuthToken(Request $request, $usedFor)
    {
        $code = InputValidation::validateCode($request->getPostParameter('code'));

        if (null === $code) {
            throw new BadRequestException('invalid_request', 'missing code');
        }
        $clientId = InputValidation::validateUri($request->getPostParameter('client_id'), 'client_id');
        $redirectUri = InputValidation::validateUri($request->getPostParameter('redirect_uri'), 'redirect_uri');

        $clientIdUriObj = new Uri($clientId);
        $redirectUriObj = new Uri($redirectUri);

        if ($clientIdUriObj->getHost() !== $redirectUriObj->getHost()) {
            throw new BadRequestException('invalid_request', 'client_id must have same host as redirect_uri');
        }

        $indieCode = $this->db->getCode($code, $clientId, $redirectUri, $usedFor);

        if (false === $indieCode) {
            throw new BadRequestException('invalid_request', 'code not found');
        }

        // the db return value is a string, not an integer, so not using !== here
        if (0 != $indieCode[$usedFor]) {
            throw new BadRequestException('invalid_request', 'code already used');
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

        $responseData = array(
            'me' => $indieCode['me'],
        );

        if (null !== $indieCode['scope']) {
            // add granted scope to response
            $responseData['scope'] = $indieCode['scope'];

            if ('used_for_token' === $usedFor) {
                // generate access token and add it to the response as well
                $accessToken = $this->io->getRandomHex();
                $this->db->storeAccessToken(
                    $accessToken,
                    $indieCode['me'],
                    $clientId,
                    $indieCode['scope'],
                    $this->io->getTime()
                );
                $responseData['access_token'] = $accessToken;
            }
        }

        $response->setContent($responseData);

        return $response;
    }

    private function indieCodeRedirect($me, $clientId, $redirectUri, $scope, $state)
    {
        // create indiecode
        $code = $this->io->getRandomHex();
        $this->db->storeIndieCode(
            $code,
            $me,
            $clientId,
            $redirectUri,
            $scope,
            $this->io->getTime()
        );

        $responseUri = sprintf('%s?me=%s&code=%s&state=%s', $redirectUri, $me, $code, $state);

        return new RedirectResponse($responseUri, 302);
    }

    private function getToken(Request $request, IndieTokenInfo $indieTokenInfo)
    {
        // default to "application/x-www-form-urlencoded" for now...
        if (false !== strpos($request->getHeader('Accept'), 'application/json')) {
            $response = new JsonResponse();
        } else {
            $response = new FormResponse();
        }

        $response->setContent(
            array(
                'me' => $indieTokenInfo->getMe(),
                'scope' => $indieTokenInfo->getScope(),
                'client_id' => $indieTokenInfo->getClientId()
            )
        );

        return $response;
    }

    private function getAccount(Request $request, UserInfo $userInfo)
    {
        $userId = $userInfo->getUserId();
        $accessTokens = $this->db->getAccessTokens($userId);
        $approvals = $this->db->getApprovals($userId);

        return $this->templateManager->render(
            'accountPage',
            array(
                'me' => $userId,
                'approvals' => $approvals,
                'tokens' => $accessTokens
            )
        );
    }
}
