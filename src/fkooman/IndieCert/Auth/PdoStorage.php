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

use PDO;

class PdoStorage
{
    /** @var PDO */
    private $db;

    /** @var string */
    private $prefix;

    public function __construct(PDO $db, $prefix = '')
    {
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db = $db;
        $this->prefix = $prefix;
    }

    public function storeIndieCode($code, $me, $clientId, $redirectUri, $issueTime)
    {
        $stmt = $this->db->prepare(
            sprintf(
                'INSERT INTO %s (code, me, client_id, redirect_uri, issue_time) VALUES(:code, :me, :client_id, :redirect_uri, :issue_time)',
                $this->prefix.'indie_codes'
            )
        );
        $stmt->bindValue(':code', $code, PDO::PARAM_STR);
        $stmt->bindValue(':me', $me, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->bindValue(':redirect_uri', $redirectUri, PDO::PARAM_STR);
        $stmt->bindValue(':issue_time', $issueTime, PDO::PARAM_INT);
        $stmt->execute();

        if (1 !== $stmt->rowCount()) {
            throw new PdoStorageException('unable to add');
        }
    }

    public function getCode($code, $clientId, $redirectUri)
    {
        // XXX: check first if it s not expired before returning it
        $stmt = $this->db->prepare(
            sprintf(
                'SELECT * FROM %s WHERE code = :code AND client_id = :client_id AND redirect_uri = :redirect_uri',
                $this->prefix.'indie_codes'
            )
        );
        $stmt->bindValue(':code', $code, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->bindValue(':redirect_uri', $redirectUri, PDO::PARAM_STR);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        $stmt = $this->db->prepare(
            sprintf(
                'DELETE FROM %s WHERE code = :code AND client_id = :client_id AND redirect_uri = :redirect_uri',
                $this->prefix.'indie_codes'
            )
        );
        $stmt->bindValue(':code', $code, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->bindValue(':redirect_uri', $redirectUri, PDO::PARAM_STR);
        $stmt->execute();

        if (1 === $stmt->rowCount()) {
            // row was updated, return the result
            return $result;
        }

        return false;
    }

    public function deleteExpiredCodes($currentTime)
    {
        $stmt = $this->db->prepare(
            sprintf(
                'DELETE FROM %s WHERE issue_time + 600 < :current_time',
                $this->prefix.'indie_codes'
            )
        );

        $stmt->bindValue(':current_time', $currentTime, PDO::PARAM_INT);

        return $stmt->execute();
    }

    public static function createTableQueries($prefix)
    {
        $query = array(
            sprintf(
                'CREATE TABLE IF NOT EXISTS %s (
                    code VARCHAR(255) NOT NULL,
                    me VARCHAR(255) NOT NULL,
                    client_id VARCHAR(255) NOT NULL,
                    redirect_uri VARCHAR(255) NOT NULL,
                    issue_time INT NOT NULL,
                    PRIMARY KEY (code)
                )',
                $prefix.'indie_codes'
            ),
        );

        return $query;
    }

    public function initDatabase()
    {
        $queries = self::createTableQueries($this->prefix);
        foreach ($queries as $q) {
            $this->db->query($q);
        }

        $tables = array('indie_codes');
        foreach ($tables as $t) {
            // make sure the tables are empty
            $this->db->query(
                sprintf(
                    'DELETE FROM %s',
                    $this->prefix.$t
                )
            );
        }
    }
}
