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

use PDO;
use PHPUnit_Framework_TestCase;
use fkooman\Http\Request;
use fkooman\Rest\Plugin\Authentication\Tls\TlsAuthentication;
use GuzzleHttp\Client;
use GuzzleHttp\Subscriber\Mock;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;
use fkooman\Tpl\Twig\TwigTemplateManager;

class IndieCertServiceTest extends PHPUnit_Framework_TestCase
{
    private $dataDir;
    private $service;

    public function setUp()
    {
        $this->dataDir = dirname(dirname(__DIR__)).'/data';

        $storage = new PdoStorage(
            new PDO(
                $GLOBALS['DB_DSN'],
                $GLOBALS['DB_USER'],
                $GLOBALS['DB_PASSWD']
            )
        );
        $storage->initDatabase();

        $ioStub = $this->getMockBuilder('fkooman\IO\IO')->getMock();
        $ioStub->method('getRandomHex')->willReturn('1234abcd');
        $ioStub->method('getTime')->willReturn(1111111111);

        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    200,
                    array('Content-Type' => 'text/html'),
                    Stream::factory(
                        file_get_contents($this->dataDir.'/fkooman.html')
                    )
                ),
            )
        );
        $client->getEmitter()->attach($mock);

        $certManager = new CertManager('crt', 'key', $ioStub);

        $tplManager = new TwigTemplateManager(
            array(dirname(dirname(dirname(__DIR__))).'/views')
        );
        $this->service = new IndieCertService($storage, $certManager, $tplManager, $client, $ioStub);
        $this->service->getPluginRegistry()->registerOptionalPlugin(new TlsAuthentication());
    }

    public function testAuthRequest()
    {
        $query = http_build_query(
            array(
                'me' => 'https://me.example/',
                'client_id' => 'https://www.client.example/client/',
                'redirect_uri' => 'https://www.client.example/client/callback',
                'state' => '12345',
            )
        );

        $request = new Request(
            array(
                'SERVER_NAME' => 'indiecert.example',
                'SERVER_PORT' => '443',
                'REQUEST_URI' => sprintf('/auth?%s', $query),
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/auth',
                'QUERY_STRING' => $query,
                'REQUEST_METHOD' => 'GET',
                'SSL_CLIENT_CERT' => file_get_contents($this->dataDir.'/2edb5c8c336b954ae2b85cb5db974ce6.pem'),
            )
        );

#        $requestUri = new Uri('https://indiecert.example/auth');
#        $requestUri->setQuery(
#            http_build_query(
#                array(
#                    'me' => 'https://me.example/',
#                    'client_id' => 'https://www.client.example/client/',
#                    'redirect_uri' => 'https://www.client.example/client/callback',
#                    'state' => '12345',
#                )
#            )
#        );
#        $request = new Request($requestUri->getUri(), 'GET');
#        $request->setRoot('/');
#        $request->setPathInfo('/auth');
#        $request->setHeaders(
#            array(
#                'SSL_CLIENT_CERT' => file_get_contents($this->dataDir.'/2edb5c8c336b954ae2b85cb5db974ce6.pem'),
#            )
#        );

        $response = $this->service->run($request);
        $this->assertEquals(
            array(
                'HTTP/1.1 200 OK',
                'Content-Type: text/html;charset=UTF-8',
                '',
                file_get_contents($this->dataDir.'/askAuthorization.html'),
            ),
            $response->toArray()
        );

#        $this->assertEquals(200, $response->getStatusCode());
#        $this->assertEquals(file_get_contents($this->dataDir.'/askAuthorization.html'), $response->getBody());
    }

#    public function testAuthRequestConfirm()
#    {
#        $requestUri = new Uri('https://indiecert.example/auth');
#        $requestUri->setQuery(
#            http_build_query(
#                array(
#                    'me' => 'https://me.example/',
#                    'client_id' => 'https://www.client.example/client/',
#                    'redirect_uri' => 'https://www.client.example/client/callback',
#                    'state' => '12345',
#                )
#            )
#        );
#        $request = new Request($requestUri->getUri(), 'POST');
#        $request->setPathInfo('/confirm');
#        $request->setRoot('/');
#        $request->setHeaders(
#            array(
#                'HTTP_REFERER' => 'https://indiecert.example/auth?me=https://me.example/&client_id=https://www.client.example/client/&redirect_uri=https://www.client.example/client/callback&state=12345',
#            )
#        );
#        $request->setPostParameters(array('x' => 'a'));
#        $request->setHeaders(
#            array(
#                'SSL_CLIENT_CERT' => file_get_contents($this->dataDir.'/2edb5c8c336b954ae2b85cb5db974ce6.pem'),
#            )
#        );

#        $response = $this->service->run($request);
#        $this->assertEquals(302, $response->getStatusCode());
#        $this->assertEquals(
#            'https://www.client.example/client/callback?me=https://me.example/&code=1234abcd&state=12345',
#            $response->getHeader('Location')
#        );

#        // now there must be a code!
#        $request = new Request('https://indiecert.example/auth', 'POST');
#        $request->setRoot('/');
#        $request->setPathInfo('/auth');
#        $request->setPostParameters(
#            array(
#                'code' => '1234abcd',
#                'client_id' => 'https://www.client.example/client/',
#                'redirect_uri' => 'https://www.client.example/client/callback',
#                'state' => '12345',
#            )
#        );
#        $response = $this->service->run($request);
#        $this->assertEquals(200, $response->getStatusCode());
#        $this->assertEquals(array('me' => 'https://me.example/'), $response->getBody());
#    }

#    public function testAuthRequestScope()
#    {
#        $requestUri = new Uri('https://indiecert.example/auth');
#        $requestUri->setQuery(
#            http_build_query(
#                array(
#                    'me' => 'https://me.example/',
#                    'client_id' => 'https://www.client.example/client/',
#                    'redirect_uri' => 'https://www.client.example/client/callback',
#                    'state' => '12345',
#                    'scope' => 'post',
#                )
#            )
#        );
#        $request = new Request($requestUri->getUri(), 'GET');
#        $request->setRoot('/');
#        $request->setPathInfo('/auth');
#        $request->setHeaders(
#            array(
#                'SSL_CLIENT_CERT' => file_get_contents($this->dataDir.'/2edb5c8c336b954ae2b85cb5db974ce6.pem'),
#            )
#        );

#        $response = $this->service->run($request);
#        $this->assertEquals(200, $response->getStatusCode());
#        $this->assertEquals(file_get_contents($this->dataDir.'/askAuthorizationScope.html'), $response->getBody());
#    }

#    public function testAuthRequestConfirmScope()
#    {
#        $requestUri = new Uri('https://indiecert.example/auth');
#        $requestUri->setQuery(
#            http_build_query(
#                array(
#                    'me' => 'https://me.example/',
#                    'client_id' => 'https://www.client.example/client/',
#                    'redirect_uri' => 'https://www.client.example/client/callback',
#                    'state' => '12345',
#                    'scope' => 'post',
#                )
#            )
#        );
#        $request = new Request($requestUri->getUri(), 'POST');
#        $request->setPathInfo('/confirm');
#        $request->setRoot('/');
#        $request->setHeaders(
#            array(
#                'HTTP_REFERER' => 'https://indiecert.example/auth?me=https://me.example/&client_id=https://www.client.example/client/&redirect_uri=https://www.client.example/client/callback&state=12345',
#            )
#        );
#        $request->setPostParameters(array('x' => 'a'));
#        $request->setHeaders(
#            array(
#                'SSL_CLIENT_CERT' => file_get_contents($this->dataDir.'/2edb5c8c336b954ae2b85cb5db974ce6.pem'),
#            )
#        );

#        $response = $this->service->run($request);
#        $this->assertEquals(302, $response->getStatusCode());
#        $this->assertEquals(
#            'https://www.client.example/client/callback?me=https://me.example/&code=1234abcd&state=12345',
#            $response->getHeader('Location')
#        );

#        // now there must be a code!
#        $request = new Request('https://indiecert.example/auth', 'POST');
#        $request->setRoot('/');
#        $request->setPathInfo('/auth');
#        $request->setPostParameters(
#            array(
#                'code' => '1234abcd',
#                'client_id' => 'https://www.client.example/client/',
#                'redirect_uri' => 'https://www.client.example/client/callback',
#                'state' => '12345',
#            )
#        );
#        $response = $this->service->run($request);
#        $this->assertEquals(200, $response->getStatusCode());
#        $this->assertEquals(array('me' => 'https://me.example/', 'scope' => 'post'), $response->getBody());
#    }
}
