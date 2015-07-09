<?php

namespace fkooman\IndieCert;

use GuzzleHttp\Client;
use DomDocument;

class CertificateValidator
{
    /** @var \GuzzleHttp\Client */
    private $client;

    public function __construct(Client $client = null)
    {
        if (null === $client) {
            $client = new Client();
        }
        $this->client = $client;
    }

    /**
     * Check if the certificate fingerprint is mentioned on the specified
     * URL.
     */
    public function hasFingerprint($homePageUrl, $fingerprint)
    {
        $fingerprint = sprintf('ni:///sha-256;%s?ct=application/x-x509-user-cert', $fingerprint);

        $htmlResponse = $this->fetchPage($homePageUrl);
        $relMeLinks = $this->extractRelMeLinks($htmlResponse);

        $certFingerprints = array();
        $pattern = '/^ni:\/\/\/sha-256;[a-zA-Z0-9_-]+\?ct=application\/x-x509-user-cert$/';

        foreach ($relMeLinks as $meLink) {
            if (1 === preg_match($pattern, $meLink)) {
                $certFingerprints[] = $meLink;
            }
        }

        if (!in_array($fingerprint, $certFingerprints)) {
            return false;
        }

        return true;
    }

    private function fetchPage($pageUrl)
    {
        // do not allow redirects to http URLs
        return $this->client->get(
            $pageUrl,
            array(
                'allow_redirects' => array(
                    'protocols' => array('https'),
                ),
            )
        )->getBody();
    }

    private function extractRelMeLinks($htmlString)
    {
        $dom = new DomDocument();
        // disable error handling by DomDocument so we handle them ourselves
        libxml_use_internal_errors(true);
        $dom->loadHTML($htmlString);
        // throw away all errors, we do not care about them anyway
        libxml_clear_errors();

        $tags = array('link', 'a');
        $relMeLinks = array();
        foreach ($tags as $tag) {
            $elements = $dom->getElementsByTagName($tag);
            foreach ($elements as $element) {
                $href = $element->getAttribute('href');
                $rel = $element->getAttribute('rel');
                // DEPRECATED: 'me' should not be used for certificate fingerprint, use publickey instead
                if ('me' === $rel) {
                    $relMeLinks[] = $href;
                }
                if ('publickey' === $rel) {
                    $relMeLinks[] = $href;
                }
            }
        }

        return $relMeLinks;
    }
}
