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

use fkooman\Http\Request;
use fkooman\IndieCert\Auth\IndieCertService;
use fkooman\IndieCert\Auth\PdoStorage;
use fkooman\Tpl\Twig\TwigTemplateManager;
use fkooman\Ini\IniReader;
use fkooman\Rest\Plugin\Authentication\AuthenticationPlugin;
use fkooman\Rest\Plugin\Authentication\IndieAuth\IndieAuthAuthentication;
use fkooman\Rest\Plugin\Authentication\Tls\TlsAuthentication;
use fkooman\Rest\Plugin\Authentication\Dummy\DummyAuthentication;
use GuzzleHttp\Client;
use fkooman\Http\Session;
use fkooman\Http\Exception\InternalServerErrorException;

try {
    $iniReader = IniReader::fromFile(
        dirname(__DIR__).'/config/config.ini'
    );

    $serverMode = $iniReader->v('serverMode', false, 'production');

    // PdoStorage
    $pdo = new PDO(
        $iniReader->v('PdoStorage', 'dsn'),
        $iniReader->v('PdoStorage', 'username', false),
        $iniReader->v('PdoStorage', 'password', false)
    );
    $db = new PdoStorage($pdo);

    // Guzzle
    $client = new Client(
        array(
            'defaults' => array(
                'verify' => 'development' !== $serverMode,
                'timeout' => 10,
            ),
        )
    );

    // TemplateManager
    $templateManager = new TwigTemplateManager(
        array(
            dirname(__DIR__).'/views',
            dirname(__DIR__).'/config/views',
        ),
        $iniReader->v('templateCache', false, null)
    );

    $session = new Session();

    $session = new Session(
        'indiecert-auth',
        array(
            'secure' => 'development' !== $serverMode,
        )
    );

    $request = new Request($_SERVER);
    $indieAuth = new IndieAuthAuthentication($templateManager, $client, $session);
    $indieAuth->setAuthUri($request->getUrl()->getRootUrl().'auth');

    $service = new IndieCertService($db, $templateManager, $client);

    $authenticationPlugin = new AuthenticationPlugin();
    $authenticationPlugin->register($indieAuth, 'indieauth');
    $authenticationPlugin->register(new TlsAuthentication(), 'user');
    //$authenticationPlugin->register(new DummyAuthentication('foo'), 'user');

    $service->getPluginRegistry()->registerDefaultPlugin($authenticationPlugin);

    $service->run($request)->send();
} catch (Exception $e) {
    // internal server error
    error_log($e->__toString());
    $e = new InternalServerErrorException($e->getMessage());
    $e->getHtmlResponse()->send();
}
