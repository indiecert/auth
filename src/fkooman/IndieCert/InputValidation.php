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

        if (false === filter_var($me, FILTER_VALIDATE_URL)) {
            throw new BadRequestException('"me" is an invalid URL');
        }

        if ('https' !== parse_url($me, PHP_URL_SCHEME)) {
            throw new BadRequestException('"me" MUST be a https URL');
        }

        if (null !== parse_url($me, PHP_URL_QUERY)) {
            throw new BadRequestException('"me" MUST NOT contain query parameters');
        }

        if (null !== parse_url($me, PHP_URL_FRAGMENT)) {
            throw new BadRequestException('"me" MUST NOT contain fragment');
        }

        // if no path is set, add '/'
        if (null === parse_url($me, PHP_URL_PATH)) {
            $me .= '/';
        }

        return $me;
    }

    public static function validateUri($uri, $fieldName)
    {
        if (null === $uri) {
            throw new BadRequestException(
                sprintf('missing parameter "%s"', $fieldName)
            );
        }

        if (false === filter_var($uri, FILTER_VALIDATE_URL)) {
            throw new BadRequestException(sprintf('"%s" is an invalid URL', $fieldName));
        }

        if ('https' !== parse_url($uri, PHP_URL_SCHEME)) {
            throw new BadRequestException(sprintf('"%s" MUST be a https URL', $fieldName));
        }

        if (null !== parse_url($uri, PHP_URL_FRAGMENT)) {
            throw new BadRequestException(sprintf('"%s" MUST NOT contain fragment', $fieldName));
        }

        return $uri;
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
            return;
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

    public static function validateRedirectTo($rootUrl, $redirectTo)
    {
        // no redirectTo specified
        if (null === $redirectTo) {
            $redirectTo = $rootUrl;
        }

        // redirectTo specified, using path relative to absRoot
        if (0 === strpos($redirectTo, '/')) {
            $redirectTo = $rootUrl.substr($redirectTo, 1);
        }

        if (false === filter_var($redirectTo, FILTER_VALIDATE_URL)) { //, FILTER_FLAG_PATH_REQUIRED)) {
            throw new BadRequestException(sprintf('invalid redirect_to URL "%s"', $redirectTo));
        }

        // URL needs to start with absRoot
        if (0 !== strpos($redirectTo, $rootUrl)) {
            throw new BadRequestException('redirect_to needs to point to a URL relative to the application root');
        }

        return $redirectTo;
    }
}
