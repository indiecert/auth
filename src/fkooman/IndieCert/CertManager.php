<?php

namespace fkooman\IndieCert;

use Crypt_RSA;
use File_X509;

class CertManager
{
    const FORMAT_PEM = 0;
    const FORMAT_DER = 1;

    /** @var string */
    private $caCrt;

    /** @var string */
    private $caKey;

    /** @var fkooman\IndieCert\IO */
    private $io;

    public function __construct($caCrt, $caKey, IO $io = null)
    {
        $this->caCrt = $caCrt;
        $this->caKey = $caKey;
        if (null === $io) {
            $io = new IO();
        }
        $this->io = $io;
    }

    public static function generateCertificateAuthority($keySize = 2048, $commonName = 'Demo CA')
    {
        $keySize = intval($keySize);
        $r = new Crypt_RSA();
        $keyData = $r->createKey($keySize);

        $privateKey = new Crypt_RSA();
        $privateKey->loadKey($keyData['privatekey']);

        $publicKey = new Crypt_RSA();
        $publicKey->loadKey($keyData['publickey']);
        $publicKey->setPublicKey();

        $subject = new File_X509();
        $subject->setDNProp('CN', $commonName);
        $subject->setPublicKey($publicKey);

        $issuer = new File_X509();
        $issuer->setPrivateKey($privateKey);
        $issuer->setDN($subject->getDN());

        $x509 = new File_X509();
        $x509->makeCA();

        $result = $x509->sign($issuer, $subject, 'sha256WithRSAEncryption');

        return array(
            'crt' => $x509->saveX509($result),
            'key' => $keyData['privatekey']
        );
    }

    public function enroll($spkac, $userAgent)
    {
        // FIXME: validate the key size
        // FIXME: validate the challenge

        if (false !== strpos($userAgent, 'Chrome')) {
            // Chrom(e)(ium) needs the certificate format to be DER
            $format = CertManager::FORMAT_DER;
        } else {
            $format = CertManager::FORMAT_PEM;
        }

        // determine serialNumber
        $commonName = $this->io->getRandomHex();
        $serialNumber = $this->io->getRandomHex();
        
        return $this->generateClientCertificate($spkac, $commonName, $serialNumber, $format);
    }

    private function generateClientCertificate($spkac, $commonName, $serialNumber, $saveFormat = CertManager::FORMAT_PEM)
    {
        $caPrivateKey = new Crypt_RSA();
        $caPrivateKey->loadKey($this->caKey);

        $issuer = new File_X509();
        $issuer->loadX509($this->caCrt);
        $issuer->setPrivateKey($caPrivateKey);

        $subject = new File_X509();
        $subject->loadCA($this->caCrt);

        // FIXME: verify challenge? and at least 2048 bits key!
        $subject->loadSPKAC($spkac);
        $subject->setDNProp('CN', $commonName);

        $x509 = new File_X509();
        // FIXME: add Subject Key Identifier?

        $x509->setSerialNumber($serialNumber, 16);

        $result = $x509->sign($issuer, $subject, 'sha256WithRSAEncryption');

        $x509->loadX509($result);
        // https://stackoverflow.com/questions/17355088/how-do-i-set-extkeyusage-with-phpseclib
        $x509->setExtension('id-ce-keyUsage', array('digitalSignature', 'keyEncipherment'), true);
        $x509->setExtension('id-ce-extKeyUsage', array('id-kp-clientAuth'));
        $x509->setExtension('id-ce-basicConstraints', array('cA' => false), true);
        $result = $x509->sign($issuer, $x509, 'sha256WithRSAEncryption');

        $format = $saveFormat === CertManager::FORMAT_PEM ? FILE_X509_FORMAT_PEM : FILE_X509_FORMAT_DER;
        return $x509->saveX509($result, $format);
    }
}
