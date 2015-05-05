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

require_once dirname(__DIR__).'/vendor/autoload.php';

use fkooman\Ini\IniReader;
use fkooman\Http\Request;
use fkooman\Http\IncomingRequest;
use fkooman\Http\Exception\HttpException;
use fkooman\Http\Exception\InternalServerErrorException;
use fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication;
use fkooman\Rest\Plugin\Bearer\BearerAuthentication;
use GuzzleHttp\Client;
use fkooman\IndieCert\CredentialValidator;
use fkooman\IndieCert\CertManager;
use fkooman\IndieCert\IndieCertService;
use fkooman\IndieCert\PdoStorage;
use fkooman\IndieCert\TemplateManager;

try {
    $iniReader = IniReader::fromFile(
        dirname(__DIR__).'/config/config.ini'
    );

    // PdoStorage
    $pdo = new PDO(
        $iniReader->v('PdoStorage', 'dsn'),
        $iniReader->v('PdoStorage', 'username', false),
        $iniReader->v('PdoStorage', 'password', false)
    );
    $db = new PdoStorage($pdo);

    // CertManager
    $caDir = $iniReader->v('CA', 'storageDir');
    $caCrt = file_get_contents(sprintf('%s/ca.crt', $caDir));
    $caKey = file_get_contents(sprintf('%s/ca.key', $caDir));

    $certManager = new CertManager($caCrt, $caKey);

    // Guzzle
    $disableServerCertCheck = $iniReader->v('disableServerCertCheck', false, false);
    $client = new Client(
        array(
            'defaults' => array(
                'verify' => !$disableServerCertCheck,
                'timeout' => 10
            )
        )
    );

    // TemplateManager
    $templateManager = new TemplateManager($iniReader->v('templateCache', false, null));

    $request = Request::fromIncomingRequest(new IncomingRequest());

    $indieAuth = new IndieAuthAuthentication($request->getAbsRoot() . 'auth');
    $indieAuth->setClient($client);
    $indieAuth->setDiscovery(false);
    $indieAuth->setUnauthorizedRedirectUri('/login');

    $bearerAuth = new BearerAuthentication(
        new CredentialValidator($db),
        'IndieCert'
    );

    $service = new IndieCertService($db, $certManager, $client, $templateManager);
    
    // enable CSRF protection
    $service->setReferrerCheck(true);

    $service->registerOnMatchPlugin(
        $indieAuth,
        array(
            'defaultDisable' => true
        )
    );
    $service->registerOnMatchPlugin(
        $bearerAuth,
        array(
            'defaultDisable' => true
        )
    );

    $service->run($request)->sendResponse();
} catch (Exception $e) {
    IndieCertService::handleException($e, false)->sendResponse();
}
