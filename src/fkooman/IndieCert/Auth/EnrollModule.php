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

use fkooman\Http\Request;
use fkooman\Http\Response;
use fkooman\Rest\Service;
use fkooman\Rest\ServiceModuleInterface;
use fkooman\IO\IO;
use fkooman\Tpl\TemplateManagerInterface;

class EnrollModule implements ServiceModuleInterface
{
    /** @var CertManager */
    private $certManager;

    /** @var \fkooman\Tpl\TemplateManagerInterface */
    private $templateManager;

    /** @var \fkooman\IO\IO */
    private $io;

    public function __construct(CertManager $certManager, TemplateManagerInterface $templateManager, IO $io = null)
    {
        $this->certManager = $certManager;
        $this->templateManager = $templateManager;

        // IO
        if (null === $io) {
            $io = new IO();
        }
        $this->io = $io;
    }

    public function init(Service $service)
    {
        $service->get(
            '/enroll',
            function (Request $request) {
                return $this->getEnroll($request);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                    'enabled' => false,
                ),
            )
        );

        $service->post(
            '/enroll',
            function (Request $request) {
                return $this->postEnroll($request);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                    'enabled' => false,
                ),
            )
        );
    }

    private function getEnroll(Request $request)
    {
        $redirectTo = $request->getUrl()->getQueryParameter('redirect_to');
        if (!is_null($redirectTo)) {
            InputValidation::validateRedirectTo($redirectTo);
        }

        $response = new Response();
        $response->setBody(
            $this->templateManager->render(
                'enrollPage',
                array(
                    'me' => $request->getUrl()->getQueryParameter('me'),
                    'certChallenge' => $this->io->getRandom(),
                    'redirectTo' => $redirectTo,
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
}
