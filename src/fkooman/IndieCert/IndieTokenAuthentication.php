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

use fkooman\Http\Request;
use fkooman\Rest\ServicePluginInterface;
use fkooman\Http\Exception\UnauthorizedException;
use fkooman\Http\Exception\BadRequestException;

class IndieTokenAuthentication implements ServicePluginInterface
{
    /* @var fkooman\IndieCert\PdoStorage */
    private $db;

    /** @var string */
    private $bearerAuthRealm;

    public function __construct(PdoStorage $db, $bearerAuthRealm = 'Protected Resource')
    {
        $this->db = $db;
        $this->bearerAuthRealm = $bearerAuthRealm;
    }

    public function execute(Request $request, array $routeConfig)
    {
        $requireAuth = true;
        if (array_key_exists('requireAuth', $routeConfig)) {
            if (!$routeConfig['requireAuth']) {
                $requireAuth = false;
            }
        }

        $headerFound = false;
        $queryParameterFound = false;

        $authorizationHeader = $request->getHeader('Authorization');
        if (0 === stripos($authorizationHeader, 'Bearer ')) {
            // Bearer header found
            $headerFound = true;
        }
        $queryParameter = $request->getQueryParameter('access_token');
        if (null !== $queryParameter) {
            // Query parameter found
            $queryParameterFound = true;
        }

        if (!$headerFound && !$queryParameterFound) {
            // none found
            if (!$requireAuth) {
                return false;
            }
            throw new UnauthorizedException(
                'invalid_token',
                'no token provided',
                'Bearer',
                array(
                    'realm' => $this->bearerAuthRealm,
                )
            );
        }
        if ($headerFound && $queryParameterFound) {
            // both found
            throw new BadRequestException(
                'invalid_request',
                'token provided through both authorization header and query string'
            );
        }
        if ($headerFound) {
            $bearerToken = substr($authorizationHeader, 7);
        } else {
            $bearerToken = $queryParameter;
        }

        // we received a Bearer token, verify the syntax
        if (!$this->isValidTokenSyntax($bearerToken)) {
            throw new BadRequestException(
                'invalid_request',
                'invalid token syntax'
            );
        }

        // we have a token that has valid syntax, look for it in the database
        $accessToken = $this->db->getAccessToken($bearerToken);
        if (false === $accessToken) {
            if (!$requireAuth) {
                return false;
            }
            throw new UnauthorizedException(
                'invalid_token',
                'token is invalid or expired',
                'Bearer',
                array(
                    'realm' => $this->bearerAuthRealm,
                    'error' => 'invalid_token',
                    'error_description' => 'token is invalid or expired',
                )
            );
        }

        return new IndieTokenInfo($accessToken);
    }

    private function isValidTokenSyntax($bearerToken)
    {
        // b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
        if (1 !== preg_match('|^[[:alpha:][:digit:]-._~+/]+=*$|', $bearerToken)) {
            return false;
        }

        return true;
    }
}
