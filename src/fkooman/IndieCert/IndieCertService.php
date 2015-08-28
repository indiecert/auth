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
                'fkooman\Rest\Plugin\Authentication\Tls\TlsAuthentication' => array(
                    'enabled' => true,
                    'require' => false,
                ),
            )
        );

        $this->post(
            '/confirm',
            function (Request $request, CertInfo $certInfo) {
                return $this->postConfirm($request, $certInfo);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\Tls\TlsAuthentication' => array(
                    'enabled' => true,
                ),
            )
        );

        // this endpoint is used for verifying authorization_code by clients
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

        $this->get(
            '/account',
            function (IndieInfo $indieInfo) {
                return $this->getAccount($indieInfo);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\IndieAuth\IndieAuthAuthentication' => array(
                    'enabled' => true,
                ),
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
                array()
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

            $response = new Response();
            $response->setBody(
                $this->templateManager->render(
                    'missingFingerprint',
                    array(
                        'me' => $me,
                        'certFingerprint' => $certInfo->getUserId(),
                        'authorizationEndpoint' => $authorizationEndpoint,
                    )
                )
            );

            return $response;
        }

        $approval = $this->db->getApproval($me, $clientId, $redirectUri);
        if (false !== $approval) {
            // check if not expired
            if ($this->io->getTime() >= $approval['expires_at']) {
                $this->db->deleteApproval($me, $clientId, $redirectUri);
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
            $confirmUri = sprintf(
                'confirm?client_id=%s&redirect_uri=%s&me=%s&state=%s',
                $clientId,
                $redirectUri,
                $me,
                $state
            );

            $response = new Response();
            $response->setBody(
                $this->templateManager->render(
                    'askConfirmation',
                    array(
                        'confirmUri' => $confirmUri,
                        'me' => $me,
                        'clientId' => $clientId,
                        'redirectUri' => $redirectUri,
                    )
                )
            );

            return $response;
        }

        return $this->indieCodeRedirect($me, $clientId, $redirectUri, $state);
    }

    private function postConfirm(Request $request, CertInfo $certInfo)
    {
        $me = InputValidation::validateMe($request->getUrl()->getQueryParameter('me'));
        $clientId = InputValidation::validateUri($request->getUrl()->getQueryParameter('client_id'), 'client_id');
        $redirectUri = InputValidation::validateUri($request->getUrl()->getQueryParameter('redirect_uri'), 'redirect_uri');
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

                $response = new Response();
                $response->setBody(
                    $this->templateManager->render(
                        'missingFingerprint',
                        array(
                            'me' => $me,
                            'certFingerprint' => $certificateValidator->getFingerprint(),
                            'authorizationEndpoint' => $authorizationEndpoint,
                        )
                    )
                );

                return $response;
            }
        }

        // store approval if requested
        if (null !== $request->getPostParameter('remember')) {
            $this->db->storeApproval($me, $clientId, $redirectUri, $this->io->getTime() + 3600 * 24 * 7);
        }

        return $this->indieCodeRedirect($me, $clientId, $redirectUri, $state);
    }

    private function postAuth(Request $request)
    {
        $code = InputValidation::validateCode($request->getPostParameter('code'));
        $clientId = InputValidation::validateUri($request->getPostParameter('client_id'), 'client_id');
        $redirectUri = InputValidation::validateUri($request->getPostParameter('redirect_uri'), 'redirect_uri');

        if (false === self::sameHost($clientId, $redirectUri)) {
            throw new BadRequestException('invalid_request', 'client_id must have same host as redirect_uri');
        }

        $indieCode = $this->db->getCode($code, $clientId, $redirectUri);

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

        $responseData = array(
            'me' => $indieCode['me'],
        );
        $response->setBody($responseData);

        return $response;
    }

    private function indieCodeRedirect($me, $clientId, $redirectUri, $state)
    {
        // create indiecode
        $code = $this->io->getRandom();
        $this->db->storeIndieCode(
            $code,
            $me,
            $clientId,
            $redirectUri,
            $this->io->getTime()
        );

        $responseUri = sprintf('%s?me=%s&code=%s&state=%s', $redirectUri, $me, $code, $state);

        return new RedirectResponse($responseUri, 302);
    }

    private function getAccount(IndieInfo $indieInfo)
    {
        $userId = $indieInfo->getUserId();
        $approvals = $this->db->getApprovals($userId);

        $response = new Response();
        $response->setBody(
            $this->templateManager->render(
                'accountPage',
                array(
                    'me' => $userId,
                    'approvals' => $approvals,
                )
            )
        );

        return $response;
    }

    private static function sameHost($u1, $u2)
    {
        // already validated using InputValidation::validateUri
        return parse_url($u1, PHP_URL_HOST) === parse_url($u2, PHP_URL_HOST);
    }
}
