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

use InvalidArgumentException;

class IndieTokenInfo
{
    /** @var array */
    private $response;

    public function __construct(array $response)
    {
        if (!isset($response['client_id']) || !is_string($response['client_id']) || 0 >= strlen($response['client_id'])) {
            throw new InvalidArgumentException('client_id key should be set and its value a string');
        }

        if (!isset($response['me']) || !is_string($response['me']) || 0 >= strlen($response['me'])) {
            throw new InvalidArgumentException('me key should be set and its value a string');
        }

        if (!isset($response['scope']) || !is_string($response['scope']) || 0 >= strlen($response['me'])) {
            throw new InvalidArgumentException('scope key should be set and its value a string');
        }

        $this->response = $response;
    }

    public function getClientId()
    {
        return $this->response['client_id'];
    }

    public function getMe()
    {
        return $this->response['me'];
    }

    public function getScope()
    {
        return $this->response['scope'];
    }
}
