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

use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\Uri;
use InvalidArgumentException;

class InputValidation
{
    public static function validateMe($me)
    {
        if (null === $me) {
            throw new BadRequestException('missing parameter "me"');
        }
        if (0 !== stripos($me, 'http')) {
            $me = sprintf('https://%s', $me);
        }
        try {
            $uriObj = new Uri($me);
            if ('https' !== $uriObj->getScheme()) {
                throw new BadRequestException('"me" must be https uri');
            }
            if (null !== $uriObj->getQuery()) {
                throw new BadRequestException('"me" cannot contain query parameters');
            }
            if (null !== $uriObj->getFragment()) {
                throw new BadRequestException('"me" cannot contain fragment');
            }

            return $uriObj->getUri();
        } catch (InvalidArgumentException $e) {
            throw new BadRequestException('"me" is an invalid uri');
        }
    }

    public static function validateUri($uri, $fieldName)
    {
        if (null === $uri) {
            throw new BadRequestException(
                sprintf('missing parameter "%s"', $fieldName)
            );
        }
        try {
            $uriObj = new Uri($uri);
            if ('https' !== $uriObj->getScheme()) {
                throw new BadRequestException(
                    sprintf('"%s" must be https uri', $fieldName)
                );
            }
            if (null !== $uriObj->getFragment()) {
                throw new BadRequestException(
                    sprintf('"%s" cannot contain fragment', $fieldName)
                );
            }

            return $uriObj->getUri();
        } catch (InvalidArgumentException $e) {
            throw new BadRequestException(
                sprintf('"%s" is an invalid uri', $fieldName)
            );
        }
    }

    public static function validateCode($code)
    {
        if (null === $code) {
            throw new BadRequestException('missing parameter "code"');
        }
        if (1 !== preg_match('/^(?:[\x20-\x7E])*$/', $code)) {
            throw new BadRequestException('"code" contains invalid characters');
        }

        return $code;
    }

    public static function validateScope($scope)
    {
        // allow scope to be missing
        if (null === $scope) {
            return null;
        }

        // but if it is there, it needs to be a valid scope and also
        // 'normalized'
        try {
            $scopeObj = new Scope($scope);
            return $scopeObj->toString();
        } catch (InvalidArgumentException $e) {
            throw new BadRequestException('"scope" is invalid', $e->getMessage());
        }
    }

    public static function validateState($state)
    {
        if (null === $state) {
            throw new BadRequestException('missing parameter "state"');
        }
        if (1 !== preg_match('/^(?:[\x20-\x7E])*$/', $state)) {
            throw new BadRequestException('"state" contains invalid characters');
        }

        return $state;
    }
}
