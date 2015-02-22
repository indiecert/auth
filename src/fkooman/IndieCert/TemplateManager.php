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

use Twig_Loader_Filesystem;
use Twig_Environment;

class TemplateManager
{

    /** @var Twig_Environment */
    private $twig;

    public function __construct()
    {
        $configTemplateDir = dirname(dirname(dirname(__DIR__))).'/config/views';
        $defaultTemplateDir = dirname(dirname(dirname(__DIR__))).'/views';

        $templateDirs = array();
        if (false !== is_dir($configTemplateDir)) {
            $templateDirs[] = $configTemplateDir;
        }
        $templateDirs[] = $defaultTemplateDir;
        $this->twig = new Twig_Environment(
            new Twig_Loader_Filesystem(
                $templateDirs
            )
        );
    }

    public function faqPage()
    {
        return $this->twig->render(
            'faqPage.twig',
            array(
            )
        );
    }

    public function welcomePage($redirectUri)
    {
        return $this->twig->render(
            'welcomePage.twig',
            array(
                'redirect_uri' => $redirectUri
            )
        );
    }

    public function authenticatedPage($me)
    {
        return $this->twig->render(
            'authenticatedPage.twig',
            array(
                'me' => $me
            )
        );
    }

    public function enrollPage($certChallenge, $referrer)
    {
        return $this->twig->render(
            'enrollPage.twig',
            array(
                'certChallenge' => $certChallenge,
                'referrer' => $referrer
            )
        );
    }

    public function askConfirmation($me, $host)
    {
        return $this->twig->render(
            'askConfirmation.twig',
            array(
                'me' => $me,
                'host' => $host
            )
        );
    }

    public function noCert()
    {
        return $this->twig->render(
            'noCert.twig',
            array(
            )
        );
    }

    public function missingFingerprint($me, $certFingerprint)
    {
        return $this->twig->render(
            'missingFingerprint.twig',
            array(
                'me' => $me,
                'certFingerprint' => $certFingerprint
            )
        );
    }
}
