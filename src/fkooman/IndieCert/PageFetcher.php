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

use Guzzle\Http\Client;
use Guzzle\Plugin\History\HistoryPlugin;
use Guzzle\Http\Url;
use RuntimeException;

class PageFetcher
{
    /* @var Guzzle\Http\Client */
    private $client;

    public function __construct(Client $client = null)
    {
        if (null === $client) {
            $client = new Client();
        }
        $this->client = $client;
    }

    public function fetch($pageUri)
    {
        $request = $this->client->get($pageUri);

        // we track all URLs on the redirect path (if any) and make sure none
        // of them redirect to a HTTP URL. Unfortunately Guzzle 3 can not do
        // this by default but we need this "hack". This is fixed in Guzzle 4+
        // see https://github.com/guzzle/guzzle/issues/841
        $history = new HistoryPlugin();
        $request->addSubscriber($history);
        $response = $request->send();

        foreach ($history->getAll() as $t) {
            if ('https' !== $t['request']->getUrl(true)->getScheme()) {
                throw new RuntimeException('redirect path contains non-HTTPS URLs');
            }
        }

        return new PageResponse($response->getEffectiveUrl(), $response->getBody());
    }
}