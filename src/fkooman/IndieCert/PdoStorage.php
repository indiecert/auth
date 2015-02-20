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

    public function storeIndieCode($me, $redirectUri, $normalizedMe, $code)
    {
        $stmt = $this->db->prepare(
            sprintf(
                'INSERT INTO %s (me, redirect_uri, normalized_me, code) VALUES(:me, :redirect_uri, :normalized_me, :code)',
                $this->prefix.'indie_codes'
            )
        );
        $stmt->bindValue(':me', $me, PDO::PARAM_STR);
        $stmt->bindValue(':redirect_uri', $redirectUri, PDO::PARAM_STR);
        $stmt->bindValue(':normalized_me', $normalizedMe, PDO::PARAM_STR);
        $stmt->bindValue(':code', $code, PDO::PARAM_STR);
        $stmt->execute();

        if (1 !== $stmt->rowCount()) {
            throw new PdoStorageException('unable to add');
        }
    }

    public function getIndieCode($code)
    {
        $stmt = $this->db->prepare(
            sprintf(
                'SELECT * FROM %s WHERE code = :code',
                $this->prefix.'indie_codes'
            )
        );
        $stmt->bindValue(':code', $code, PDO::PARAM_STR);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        $stmt = $this->db->prepare(
            sprintf(
                'DELETE FROM %s WHERE code = :code',
                $this->prefix.'indie_codes'
            )
        );
        $stmt->bindValue(':code', $code, PDO::PARAM_STR);
        $stmt->execute();

        if (1 === $stmt->rowCount()) {
            // code was deleted, return the result
            return $result;
        }

        return false;
    }

    public function storeCertificate($commonName)
    {
        $stmt = $this->db->prepare(
            sprintf(
                'INSERT INTO %s (common_name) VALUES(:common_name)',
                $this->prefix.'indie_certificates'
            )
        );
        $stmt->bindValue(':common_name', $commonName, PDO::PARAM_STR);
        $stmt->execute();

        if (1 !== $stmt->rowCount()) {
            throw new PdoStorageException('unable to add');
        }
        
        return $this->db->lastInsertId();
    }

    public static function createTableQueries($prefix)
    {
        $query = array();

        $query[] = sprintf(
            'CREATE TABLE IF NOT EXISTS %s (
                code VARCHAR(255) NOT NULL,
                me VARCHAR(255) NOT NULL,
                redirect_uri VARCHAR(255) NOT NULL,
                normalized_me VARCHAR(255) NOT NULL,
                PRIMARY KEY (code)
            )',
            $prefix.'indie_codes'
        );

        $query[] = sprintf(
            'CREATE TABLE IF NOT EXISTS %s (
                common_name VARCHAR(255) NOT NULL
            )',
            $prefix.'indie_certificates'
        );

        return $query;
    }

    public function initDatabase()
    {
        $queries = self::createTableQueries($this->prefix);
        foreach ($queries as $q) {
            $this->db->query($q);
        }

        $tables = array('indie_codes', 'indie_certificates');
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
