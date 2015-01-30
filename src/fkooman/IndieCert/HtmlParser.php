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

use DomDocument;

class HtmlParser
{
    private $dom;

    public function __construct()
    {
        $this->dom = new DomDocument();
    }

    public function getRelLinks($htmlString)
    {
        // disable error handling by DomDocument so we handle them ourselves
        libxml_use_internal_errors(true);
        $this->dom->loadHTML($htmlString);
        // throw away all errors, we do not care about them anyway
        libxml_clear_errors();

        $tags = array('link', 'a');
        $links = array();
        foreach ($tags as $tag) {
            $elements = $this->dom->getElementsByTagName($tag);
            foreach ($elements as $element) {
                $href = $element->getAttribute('href');
                $rel = $element->getAttribute('rel');
                if ('me' === $rel) {
                    $links[] = $href;
                }
            }
        }
        return $links;
    }
}
