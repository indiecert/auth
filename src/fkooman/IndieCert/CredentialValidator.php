<?php

/**
 * Copyright 2014 François Kooman <fkooman@tuxed.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace fkooman\IndieCert;

use fkooman\Rest\Plugin\Authentication\Bearer\ValidatorInterface;
use fkooman\Rest\Plugin\Authentication\Bearer\TokenInfo;

/**
 * Check whether the credentials used to authenticate to the introspection
 * endpoint are valid.
 *
 * The introspection endpoint itself requires "Bearer" authentication, and is
 * meant to be used by protected services that want to validate Bearer tokens.
 */
class CredentialValidator implements ValidatorInterface
{
    /** @var PdoStorage */
    private $db;

    public function __construct(PdoStorage $db)
    {
        $this->db = $db;
    }

    public function validate($bearerToken)
    {
        $credential = $this->db->getCredential($bearerToken);
        if (false === $credential) {
            return new TokenInfo(
                array(
                    'active' => false,
                )
            );
        }

        return new TokenInfo(
            array(
                'active' => true,
            )
        );
    }
}
