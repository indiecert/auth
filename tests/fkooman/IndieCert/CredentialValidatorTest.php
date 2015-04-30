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

class CredentialValidatorTest extends PHPUnit_Framework_TestCase
{
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

    public function testNonExistingCredential()
    {
        $c = new CredentialValidator($this->db);
        $tokenInfo = $c->validate('foo');
        $this->assertFalse($tokenInfo->get('active'));
    }

    public function testExistingCredential()
    {
        $this->db->storeCredential('https://www.example.org/', 'foo', '123456');
        $c = new CredentialValidator($this->db);
        $tokenInfo = $c->validate('foo');
        $this->assertTrue($tokenInfo->get('active'));
    }
}
