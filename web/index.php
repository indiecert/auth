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
use fkooman\Http\Exception\HttpException;
use fkooman\Http\Exception\InternalServerErrorException;
use fkooman\IndieCert\IndieCertService;
use fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication;
use fkooman\IndieCert\PdoStorage;
use GuzzleHttp\Client;
use fkooman\Http\Request;
use fkooman\Http\IncomingRequest;

try {
    $iniReader = IniReader::fromFile(
        dirname(__DIR__).'/config/config.ini'
    );

    $caDir = $iniReader->v('CA', 'storageDir');
    $caCrt = file_get_contents(sprintf('%s/ca.crt', $caDir));
    $caKey = file_get_contents(sprintf('%s/ca.key', $caDir));

    // STORAGE
    $pdo = new PDO(
        $iniReader->v('PdoStorage', 'dsn'),
        $iniReader->v('PdoStorage', 'username', false),
        $iniReader->v('PdoStorage', 'password', false)
    );
    $pdoStorage = new PdoStorage($pdo);

    // HTTP CLIENT
    $disableServerCertCheck = $iniReader->v('disableServerCertCheck', false, false);

    $client = new Client(
        array(
            'defaults' => array(
                'verify' => !$disableServerCertCheck,
                'timeout' => 5
            )
        )
    );

    $request = Request::fromIncomingRequest(new IncomingRequest());
    $indieAuth = new IndieAuthAuthentication($request->getAbsRoot() . 'auth');
    $indieAuth->setClient($client);
    $indieAuth->setDiscovery(false);

    $service = new IndieCertService($caCrt, $caKey, $pdoStorage, $client);
    $service->registerOnMatchPlugin($indieAuth);
    $service->run($request)->sendResponse();
} catch (Exception $e) {
    error_log(
        $e->getMessage()
    );
    IndieCertService::handleException($e)->sendResponse();
}
