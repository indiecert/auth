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
use RuntimeException;

class TemplateManager
{
    /** @var Twig_Environment */
    private $twig;

    /** @var array */
    private $globalVariables;

    public function __construct($cacheDir = null)
    {
        $configTemplateDir = dirname(dirname(dirname(__DIR__))).'/config/views';
        $defaultTemplateDir = dirname(dirname(dirname(__DIR__))).'/views';

        $templateDirs = array();
        if (false !== is_dir($configTemplateDir)) {
            $templateDirs[] = $configTemplateDir;
        }
        $templateDirs[] = $defaultTemplateDir;

        $environmentOptions = array(
            'strict_variables' => true,
        );

        if (null !== $cacheDir) {
            if (false === is_dir($cacheDir)) {
                if (false === @mkdir($cacheDir)) {
                    throw new RuntimeException('unable to create template cache directory');
                }
            }
            $environmentOptions['cache'] = $cacheDir;
        }

        $this->twig = new Twig_Environment(
            new Twig_Loader_Filesystem(
                $templateDirs
            ),
            $environmentOptions
        );

        $this->globalVariables = array();
    }

    public function setGlobalVariables(array $globalVariables)
    {
        $this->globalVariables = $globalVariables;
    }

    public function render($templateName, array $variables = array())
    {
        $variables = array_merge($this->globalVariables, $variables);

        return $this->twig->render(
            sprintf(
                '%s.twig',
                $templateName
            ),
            $variables
        );
    }
}
