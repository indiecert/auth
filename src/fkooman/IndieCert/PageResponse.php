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

class PageResponse
{
    /** @var string */
    private $effectiveUrl;

    /** @var string */
    private $body;

    public function __construct($effectiveUrl, $body)
    {
        $this->effectiveUrl = $effectiveUrl;
        $this->body = $body;
    }

    public function getEffectiveUrl()
    {
        return $this->effectiveUrl;
    }

    public function getBody()
    {
        return $this->body;
    }
}
