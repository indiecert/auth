<?php

namespace fkooman\IndieCert;

use fkooman\X509\CertParser;
use fkooman\X509\CertParserException;
use GuzzleHttp\Client;
use GuzzleHttp\Subscriber\History;
use GuzzleHttp\Url;
use RuntimeException;
use DomDocument;

class CertificateValidator
{

    /** @var fkooman\X509\CertParser */
    private $certParser;

    /** @var GuzzleHttp\Client */
    private $client;

    public function __construct($certificateData, Client $client = null)
    {
        $this->certParser = new CertParser($certificateData);

        if (null === $client) {
            $client = new Client();
        }
        $this->client = $client;
    }

    /**
     * Get the fingerprint of the certificate in RFC 6920 format
     */
    public function getFingerprint()
    {
        return sprintf(
            'ni:///sha-256;%s?ct=application/x-x509-user-cert',
            $this->certParser->getFingerPrint('sha256', true)
        );
    }

    /**
     * Check if the certificate fingerprint is mentioned on the specified
     * URL
     */
    public function hasFingerprint($homePageUrl)
    {
        $htmlResponse = $this->fetchPage($homePageUrl);
        $relMeLinks = $this->extractRelMeLinks($htmlResponse);

        $certFingerprints = array();
        $pattern = '/^ni:\/\/\/sha-256;[a-zA-Z0-9_-]+\?ct=application\/x-x509-user-cert$/';

        foreach ($relMeLinks as $meLink) {
            if (1 === preg_match($pattern, $meLink)) {
                $certFingerprints[] = $meLink;
            }
        }

        if (!in_array($this->getFingerprint(), $certFingerprints)) {
            return false;
        }

        return true;
    }

    private function fetchPage($pageUri)
    {
        // we track all URLs on the redirect path (if any) and make sure none
        // of them redirect to a HTTP URL. Unfortunately Guzzle 3/4 can not do
        // this by default but we need this "hack". This is fixed in Guzzle 5+
        // see https://github.com/guzzle/guzzle/issues/841
        $history = new History();
        $this->client->getEmitter()->attach($history);

        $request = $this->client->createRequest('GET', $pageUri);
        $response = $this->client->send($request);

        foreach ($history as $transaction) {
            $u = Url::fromString($transaction['request']->getUrl());
            if ('https' !== $u->getScheme()) {
                throw new RuntimeException('redirect path contains non-HTTPS URLs');
            }
        }

        return $response->getBody();
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
                if ('me' === $rel) {
                    $relMeLinks[] = $href;
                }
            }
        }

        return $relMeLinks;
    }
}
