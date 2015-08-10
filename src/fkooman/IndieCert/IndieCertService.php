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

use fkooman\IO\IO;
use fkooman\Http\Request;
use fkooman\Http\Response;
use fkooman\Http\JsonResponse;
use fkooman\Http\FormResponse;
use fkooman\Rest\Service;
use GuzzleHttp\Client;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\Exception\UnauthorizedException;
use fkooman\Rest\Plugin\Authentication\Bearer\TokenInfo;
use fkooman\Rest\Plugin\Authentication\IndieAuth\IndieInfo;
use fkooman\Rest\Plugin\Authentication\Tls\CertInfo;
use fkooman\Tpl\TemplateManagerInterface;

class IndieCertService extends Service
{
    /** @var PdoStorage */
    private $db;

    /** @var CertManager */
    private $certManager;

    /** @var \fkooman\Tpl\TemplateManagerInterface */
    private $templateManager;

    /** @var \GuzzleHttp\Client */
    private $client;

    /** @var \fkooman\IO\IO */
    private $io;

    public function __construct(PdoStorage $db, CertManager $certManager, TemplateManagerInterface $templateManager, Client $client = null, IO $io = null)
    {
        parent::__construct();

        $this->db = $db;
        $this->certManager = $certManager;
        $this->templateManager = $templateManager;

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
            function (Request $request, CertInfo $certInfo = null) {
                return $this->getAuth($request, $certInfo);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\Tls\TlsAuthentication' => array('enabled' => true, 'require' => false),
            )
        );

        $this->post(
            '/confirm',
            function (Request $request, CertInfo $certInfo) {
                return $this->postConfirm($request, $certInfo);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\Tls\TlsAuthentication' => array('enabled' => true),
            )
        );

        // this endpoint is used for verifying authorization_code by clients that
        // only want to use authentication and not obtain an access_token
        $this->post(
            '/auth',
            function (Request $request) {
                return $this->postAuth($request);
            }
        );

        $this->get(
            '/login',
            function (Request $request) {
                return $this->getLogin($request);
            }
        );

        $this->post(
            '/introspect',
            function (Request $request, TokenInfo $tokenInfo) {
                return $this->verifyToken($request, $tokenInfo);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\Bearer\BearerAuthentication' => array('enabled' => true),
            )
        );

        // this endpoint is used by clients to exchange authorization_code
        // for an access_token in case a scope was requested
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
        $this->delete(
            '/token/:id',
            function (Request $request, IndieInfo $indieInfo, $id) {
                return $this->deleteToken($request, $indieInfo, $id);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\IndieAuth\IndieAuthAuthentication' => array('enabled' => true),
            )
        );

        $this->get(
            '/account',
            function (IndieInfo $indieInfo) {
                return $this->getAccount($indieInfo);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\IndieAuth\IndieAuthAuthentication' => array('enabled' => true),
            )
        );

        $this->post(
            '/credential',
            function (Request $request, IndieInfo $indieInfo) {
                return $this->generateCredential($request, $indieInfo);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\IndieAuth\IndieAuthAuthentication' => array('enabled' => true),
            )
        );

        $this->delete(
            '/credential',
            function (Request $request, IndieInfo $indieInfo) {
                return $this->deleteCredential($request, $indieInfo);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\IndieAuth\IndieAuthAuthentication' => array('enabled' => true),
            )
        );
    }

    private function getIndex(Request $request)
    {
        $redirectUri = $request->getUrl()->getRootUrl().'cb';

        $response = new Response();
        $response->setBody(
            $this->templateManager->render(
                'indexPage',
                array(
                    'redirect_uri' => $redirectUri,
                )
            )
        );

        return $response;
    }

    private function getFaq(Request $request)
    {
        $response = new Response();
        $response->setBody(
            $this->templateManager->render(
                'faqPage',
                array(
                    'introspect_endpoint' => $request->getUrl()->getRootUrl().'introspect',
                )
            )
        );

        return $response;
    }

    private function getRp(Request $request)
    {
        $authUri = $request->getUrl()->getRootUrl().'auth';
        $verifyPath = $request->getUrl()->getRoot().'auth';
        $hostName = $request->getUrl()->getHost();

        $response = new Response();
        $response->setBody(
            $this->templateManager->render(
                'relyingPartyPage',
                array(
                    'authUri' => $authUri,
                    'verifyPath' => $verifyPath,
                    'hostName' => $hostName,
                )
            )
        );

        return $response;
    }

    private function getLogin(Request $request)
    {
        $redirectTo = null;
        if (null !== $request->getUrl()->getQueryParameter('redirect_to')) {
            $redirectTo = InputValidation::validateRedirectTo($request->getUrl()->getRootUrl(), $request->getUrl()->getQueryParameter('redirect_to'));
        }

        $response = new Response();
        $response->setBody(
            $this->templateManager->render(
                'loginPage',
                array(
                    'redirect_to' => $redirectTo,
                )
            )
        );

        return $response;
    }

    private function getEnroll(Request $request)
    {
        $response = new Response();
        $response->setBody(
            $this->templateManager->render(
                'enrollPage',
                array(
                    'me' => $request->getUrl()->getQueryParameter('me'),
                    'certChallenge' => $this->io->getRandom(),
                    'referrer' => $request->getHeader('HTTP_REFERER'),
                )
            )
        );

        return $response;
    }

    private function postEnroll(Request $request)
    {
        $userCert = $this->certManager->enroll(
            $request->getPostParameter('spkac'),
            $request->getPostParameter('me'),
            $request->getHeader('USER_AGENT')
        );

        $response = new Response(200, 'application/x-x509-user-cert');
        $response->setBody($userCert);

        return $response;
    }

    private function getAuth(Request $request, CertInfo $certInfo = null)
    {
        $me = InputValidation::validateMe($request->getUrl()->getQueryParameter('me'));
        $clientId = InputValidation::validateUri($request->getUrl()->getQueryParameter('client_id'), 'client_id');
        $redirectUri = InputValidation::validateUri($request->getUrl()->getQueryParameter('redirect_uri'), 'redirect_uri');
        $scope = InputValidation::validateScope($request->getUrl()->getQueryParameter('scope'));
        $state = InputValidation::validateState($request->getUrl()->getQueryParameter('state'));

        if (false === self::sameHost($clientId, $redirectUri)) {
            throw new BadRequestException('invalid_request', 'client_id must have same host as redirect_uri');
        }

        if (null === $certInfo) {
            return $this->templateManager->render(
                'noCert',
                array(
                    'me' => $me,
                )
            );
        }

        $certificateValidator = new CertificateValidator($this->client);
        if (false === $certificateValidator->hasFingerprint($me, $certInfo->getUserId())) {
            $authorizationEndpoint = $request->getUrl()->getRootUrl().'auth';
            $tokenEndpoint = $request->getUrl()->getRootUrl().'token';

            $response = new Response();
            $response->setBody(
                $this->templateManager->render(
                    'missingFingerprint',
                    array(
                        'me' => $me,
                        'certFingerprint' => $certInfo->getUserId(),
                        'authorizationEndpoint' => $authorizationEndpoint,
                        'tokenEndpoint' => $tokenEndpoint,
                    )
                )
            );

            return $response;
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

            // store in apcu cache that the verification of the fingerprint
            // was successful, we do not have a user session to keep track of
            // this kind of stuff
            if (function_exists('apc_add')) {
                apc_add($me, true);
            }

            // FIXME: we could just get the query parameters... they were
            // validated anyway...
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

            $response = new Response();
            $response->setBody(
                $this->templateManager->render(
                    'askConfirmation',
                    array(
                        'confirmUri' => $confirmUri,
                        'me' => $me,
                        'clientId' => $clientId,
                        'redirectUri' => $redirectUri,
                        'scope' => $scope,
                    )
                )
            );

            return $response;
        }

        return $this->indieCodeRedirect($me, $clientId, $redirectUri, $scope, $state);
    }

    private function postConfirm(Request $request, CertInfo $certInfo)
    {
        $me = InputValidation::validateMe($request->getUrl()->getQueryParameter('me'));
        $clientId = InputValidation::validateUri($request->getUrl()->getQueryParameter('client_id'), 'client_id');
        $redirectUri = InputValidation::validateUri($request->getUrl()->getQueryParameter('redirect_uri'), 'redirect_uri');
        $scope = InputValidation::validateScope($request->getUrl()->getQueryParameter('scope'));
        $state = InputValidation::validateState($request->getUrl()->getQueryParameter('state'));

        if (null === $certInfo) {
            $response = new Response();
            $response->setBody(
                $this->templateManager->render(
                    'noCert',
                    array(
                        'me' => $me,
                    )
                )
            );

            return $response;
        }

        $confirmedFingerprint = false;
        if (function_exists('apc_fetch') && function_exists('apc_delete')) {
            if (false !== apc_fetch($me)) {
                // we got confirmation
                $confirmedFingerprint = true;
                // delete the key from the cache
                apc_delete($me);
            }
        }

        if (!$confirmedFingerprint) {
            $certificateValidator = new CertificateValidator($this->client);

            if (false === $certificateValidator->hasFingerprint($me, $certInfo->getUserId())) {
                $authorizationEndpoint = $request->getUrl()->getRootUrl().'auth';
                $tokenEndpoint = $request->getUrl()->getRootUrl().'token';

                $response = new Response();
                $response->setBody(
                    $this->templateManager->render(
                        'missingFingerprint',
                        array(
                            'me' => $me,
                            'certFingerprint' => $certificateValidator->getFingerprint(),
                            'authorizationEndpoint' => $authorizationEndpoint,
                            'tokenEndpoint' => $tokenEndpoint,
                        )
                    )
                );

                return $response;
            }
        }

        // store approval if requested
        if (null !== $request->getPostParameter('remember')) {
            $this->db->storeApproval($me, $clientId, $redirectUri, $scope, $this->io->getTime() + 3600 * 24 * 7);
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
        $clientId = InputValidation::validateUri($request->getPostParameter('client_id'), 'client_id');
        $redirectUri = InputValidation::validateUri($request->getPostParameter('redirect_uri'), 'redirect_uri');

        if (false === self::sameHost($clientId, $redirectUri)) {
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
                $accessToken = $this->io->getRandom();
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

        $response->setBody($responseData);

        return $response;
    }

    private function indieCodeRedirect($me, $clientId, $redirectUri, $scope, $state)
    {
        // create indiecode
        $code = $this->io->getRandom();
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

    private function verifyToken(Request $request, TokenInfo $tokenInfo)
    {
        // validate the request is properly authenticated
        // FIXME: this is never triggered, we MUST assume if bearer authorization
        // token is set it is an attempt at verifying the token...
        if (!$tokenInfo->get('active')) {
            throw new UnauthorizedException('', '');
        }

        $token = $request->getPostParameter('token');
        if (null === $token) {
            throw new BadRequestException('invalid_request', 'token parameter missing');
        }

        $accessToken = $this->db->getAccessToken($token);
        if (false === $accessToken) {
            $tokenInfo = array(
                'active' => false,
            );
        } else {
            $tokenInfo = array(
                'active' => true,
                'sub' => $accessToken['me'],
                'scope' => $accessToken['scope'],
                'client_id' => $accessToken['client_id'],
                'iat' => intval($accessToken['issue_time']),
            );
        }

        $response = new JsonResponse();
        $response->setBody($tokenInfo);

        return $response;
    }

    private function getAccount(IndieInfo $indieInfo)
    {
        $userId = $indieInfo->getUserId();
        $accessTokens = $this->db->getAccessTokens($userId);
        $approvals = $this->db->getApprovals($userId);
        $credential = $this->db->getCredentialForUser($userId);

        $response = new Response();
        $response->setBody(
            $this->templateManager->render(
                'accountPage',
                array(
                    'me' => $userId,
                    'approvals' => $approvals,
                    'tokens' => $accessTokens,
                    'credential' => $credential,
                )
            )
        );

        return $response;
    }

    private function generateCredential(Request $request, IndieInfo $indieInfo)
    {
        $credential = $this->io->getRandom();
        $issueTime = $this->io->getTime();
        $this->db->storeCredential($indieInfo->getUserId(), $credential, $issueTime);

        return new RedirectResponse($request->getUrl()->getRootUrl().'account#credentials', 302);
    }

    private function deleteCredential(Request $request, IndieInfo $indieInfo)
    {
        $this->db->deleteCredential($indieInfo->getUserId());

        return new RedirectResponse($request->getUrl()->getRootUrl().'account#credentials', 302);
    }

    private function deleteToken(Request $request, IndieInfo $indieInfo, $id)
    {
        $this->db->deleteAccessToken($indieInfo->getUserId(), $id);

        return new RedirectResponse($request->getUrl()->getRootUrl().'account#access_tokens', 302);
    }

    private static function sameHost($u1, $u2)
    {
        // already validated using InputValidation::validateUri
        return parse_url($u1, PHP_URL_HOST) === parse_url($u2, PHP_URL_HOST);
    }
}
