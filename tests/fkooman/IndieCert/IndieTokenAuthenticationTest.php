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
use fkooman\Http\Uri;
use GuzzleHttp\Client;
use GuzzleHttp\Subscriber\Mock;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;

class IndieTokenAuthenticationTest extends PHPUnit_Framework_TestCase
{
    /** @var fkooman\IndieCert\PdoStorage */
    private $db;

    public function setUp()
    {
        $this->db = new PdoStorage(
            new PDO(
                $GLOBALS['DB_DSN'],
                $GLOBALS['DB_USER'],
                $GLOBALS['DB_PASSWD']
            )
        );
        $this->db->initDatabase();
    }

    public function testIndieTokenSimple()
    {
        $this->db->storeAccessToken(
            'xyz',
            'https://fkooman.example/',
            'https://app.example/',
            'post',
            time()
        );

        $request = new Request('https://indiecert.example/token', 'GET');
        $request->setHeaders(
            array(
                'Authorization' => 'Bearer xyz'
            )
        );
 
        $ita = new IndieTokenAuthentication($this->db, 'IndieCert');
        $response = $ita->execute($request, array());
        $this->assertEquals('https://fkooman.example/', $response->getMe());
        $this->assertEquals('https://app.example/', $response->getClientId());
        $this->assertEquals('post', $response->getScope());
    }
}
