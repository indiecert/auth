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
namespace fkooman\IndieCert\Auth;

use fkooman\IO\IO;
use fkooman\Http\Request;
use fkooman\Http\JsonResponse;
use fkooman\Http\FormResponse;
use fkooman\Rest\Service;
use GuzzleHttp\Client;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Rest\Plugin\Authentication\UserInfoInterface;
use fkooman\Tpl\TemplateManagerInterface;

class IndieCertService extends Service
{
    /** @var PdoStorage */
    private $db;

    /** @var \fkooman\Tpl\TemplateManagerInterface */
    private $templateManager;

    /** @var \GuzzleHttp\Client */
    private $client;

    /** @var \fkooman\IO\IO */
    private $io;

    /** @var string */
    private $enrollUrl;

    public function __construct(PdoStorage $db, TemplateManagerInterface $templateManager, Client $client = null, IO $io = null)
    {
        parent::__construct();

        $this->db = $db;
        $this->templateManager = $templateManager;

        // Guzzle
        if (is_null($client)) {
            $client = new Client();
        }
        $this->client = $client;

        // IO
        if (is_null($io)) {
            $io = new IO();
        }
        $this->io = $io;

        $this->enrollUrl = null;

        $this->registerRoutes();
    }

    public function setEnrollUrl($enrollUrl)
    {
        $this->enrollUrl = $enrollUrl;
    }

    private function registerRoutes()
    {
        // Autentication NOT needed
        $this->get(
            '/',
            function (Request $request) {
                return $this->getIndex($request);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                    'enabled' => false,
                ),
            )
        );

        $this->get(
            '/faq',
            function (Request $request) {
                return $this->getFaq($request);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                    'enabled' => false,
                ),
            )
        );

        $this->get(
            '/auth',
            function (Request $request, UserInfoInterface $userInfo = null) {
                return $this->getAuth($request, $userInfo);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                    'activate' => array('user'),
                    'require' => false,
                ),
            )
        );

        $this->post(
            '/confirm',
            function (Request $request, UserInfoInterface $userInfo) {
                return $this->postConfirm($request, $userInfo);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                    'activate' => array('user'),
                ),
            )
        );

        // this endpoint is used for verifying authorization_code by clients
        $this->post(
            '/auth',
            function (Request $request) {
                return $this->postAuth($request);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                    'enabled' => false,
                ),
            )
        );
    }

    private function getIndex(Request $request)
    {
        return $this->templateManager->render(
            'indexPage', array()
        );
    }

    private function getFaq(Request $request)
    {
        return $this->templateManager->render(
            'faqPage', array()
        );
    }

    private function getAuth(Request $request, UserInfoInterface $userInfo = null)
    {
        $me = InputValidation::validateMe($request->getUrl()->getQueryParameter('me'));
        $clientId = InputValidation::validateUri($request->getUrl()->getQueryParameter('client_id'), 'client_id');
        $redirectUri = InputValidation::validateUri($request->getUrl()->getQueryParameter('redirect_uri'), 'redirect_uri');
        $state = InputValidation::validateState($request->getUrl()->getQueryParameter('state'));

        if (false === self::sameHost($clientId, $redirectUri)) {
            throw new BadRequestException('invalid_request', '"client_id" must have same host as "redirect_uri"');
        }

        if (is_null($userInfo)) {
            return $this->templateManager->render(
                'noCert',
                array(
                    'enrollUrl' => $this->enrollUrl,
                    'me' => $me,
                )
            );
        }

        $certificateValidator = new CertificateValidator($this->client);
        if (false === $certificateValidator->hasFingerprint($me, $userInfo->getUserId())) {
            $authorizationEndpoint = $request->getUrl()->getRootUrl().'auth';

            return $this->templateManager->render(
                'missingFingerprint',
                array(
                    'me' => $me,
                    'certFingerprint' => $userInfo->getUserId(),
                    'authorizationEndpoint' => $authorizationEndpoint,
                )
            );
        }

        // store in apcu cache that the verification of the fingerprint
        // was successful, we do not have a user session to keep track of
        // this kind of stuff
        // XXX: is this secure?
        if (function_exists('apc_add')) {
            apc_add($me, true);
        }

        // XXX: we could just get the query parameters... they were
        // validated anyway... or can we?
        $confirmUri = sprintf(
            'confirm?client_id=%s&redirect_uri=%s&me=%s&state=%s',
            $clientId,
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
                'redirectUri' => $redirectUri,
            )
        );
    }

    private function postConfirm(Request $request, UserInfoInterface $userInfo)
    {
        $me = InputValidation::validateMe($request->getUrl()->getQueryParameter('me'));
        $clientId = InputValidation::validateUri($request->getUrl()->getQueryParameter('client_id'), 'client_id');
        $redirectUri = InputValidation::validateUri($request->getUrl()->getQueryParameter('redirect_uri'), 'redirect_uri');
        $state = InputValidation::validateState($request->getUrl()->getQueryParameter('state'));

        if (is_null($userInfo)) {
            return $this->templateManager->render(
                'noCert',
                array(
                    'enrollUrl' => $this->enrollUrl,
                    'me' => $me,
                )
            );
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
            // XXX: move this to common function?
            $certificateValidator = new CertificateValidator($this->client);

            if (false === $certificateValidator->hasFingerprint($me, $userInfo->getUserId())) {
                $authorizationEndpoint = $request->getUrl()->getRootUrl().'auth';

                return $this->templateManager->render(
                    'missingFingerprint',
                    array(
                        'me' => $me,
                        'certFingerprint' => $userInfo->getUserId(),
                        'authorizationEndpoint' => $authorizationEndpoint,
                    )
                );
            }
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

        $response->setBody(
            array(
                'me' => $indieCode['me'],
            )
        );

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

    private static function sameHost($u1, $u2)
    {
        // already validated using InputValidation::validateUri
        return parse_url($u1, PHP_URL_HOST) === parse_url($u2, PHP_URL_HOST);
    }
}
