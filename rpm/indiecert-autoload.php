<?php
$vendorDir = '/usr/share/php';
$pearDir   = '/usr/share/pear';
$baseDir   = dirname(__DIR__);

require_once $vendorDir.'/Symfony/Component/ClassLoader/UniversalClassLoader.php';

use Symfony\Component\ClassLoader\UniversalClassLoader;

$loader = new UniversalClassLoader();
$loader->registerNamespaces(
    array(
        'fkooman\\IndieCert' => $baseDir.'/src',
        'fkooman\\Rest'      => $vendorDir,
        'fkooman\\Json'      => $vendorDir,
        'fkooman\\Ini'       => $vendorDir,
        'fkooman\\X509'      => $vendorDir,
        'fkooman\\Http'      => $vendorDir,
        'GuzzleHttp\\Stream' => $vendorDir,
        'GuzzleHttp'         => $vendorDir
    )
);

$loader->registerPrefixes(array(
    'Twig_'  => array($pearDir, $vendorDir),
    'File_'  => array($pearDir, $vendorDir),
    'Crypt_' => array($pearDir, $vendorDir)
));

$loader->register();

require_once $vendorDir.'/GuzzleHttp/functions.php';
require_once $vendorDir.'/GuzzleHttp/Stream/functions.php';
