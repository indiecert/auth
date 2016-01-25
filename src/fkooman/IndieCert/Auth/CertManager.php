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
namespace fkooman\IndieCert\Auth;

use phpseclib\Crypt\RSA;
use phpseclib\File\X509;
use fkooman\IO\IO;

class CertManager
{
    const FORMAT_PEM = 0;
    const FORMAT_DER = 1;

    /** @var string */
    private $caCrt;

    /** @var string */
    private $caKey;

    /** @var \fkooman\IO\IO */
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
        $r = new RSA();
        $keyData = $r->createKey($keySize);

        $privateKey = new RSA();
        $privateKey->loadKey($keyData['privatekey']);

        $publicKey = new RSA();
        $publicKey->loadKey($keyData['publickey']);
        $publicKey->setPublicKey();

        $subject = new X509();
        $subject->setDNProp('CN', $commonName);
        $subject->setPublicKey($publicKey);

        $issuer = new X509();
        $issuer->setPrivateKey($privateKey);
        $issuer->setDN($subject->getDN());

        $x509 = new X509();
        $x509->makeCA();

        $result = $x509->sign($issuer, $subject, 'sha256WithRSAEncryption');

        return array(
            'crt' => $x509->saveX509($result),
            'key' => $keyData['privatekey'],
        );
    }

    public function enroll($spkac, $me, $userAgent)
    {
        // FIXME: validate the key size
        // FIXME: validate the challenge
        // FIXME: validate me

        if (false !== strpos($userAgent, 'Chrome')) {
            // Chrom(e)(ium) needs the certificate format to be DER
            $format = self::FORMAT_DER;
        } else {
            $format = self::FORMAT_PEM;
        }

        // determine serialNumber
        $commonName = $this->io->getRandom();
        $serialNumber = $this->io->getRandom();

        return $this->generateClientCertificate($spkac, $me, $commonName, $serialNumber, $format);
    }

    private function generateClientCertificate($spkac, $me, $commonName, $serialNumber, $saveFormat = self::FORMAT_PEM)
    {
        $caPrivateKey = new RSA();
        $caPrivateKey->loadKey($this->caKey);

        $issuer = new X509();
        $issuer->loadX509($this->caCrt);
        $issuer->setPrivateKey($caPrivateKey);

        $subject = new X509();
        $subject->loadCA($this->caCrt);

        // FIXME: verify challenge? and at least 2048 bits key!
        $subject->loadSPKAC($spkac);
        $subject->setDNProp('CN', $commonName);

        $x509 = new X509();
        // FIXME: add Subject Key Identifier?

        $x509->setSerialNumber($serialNumber, 16);

        $result = $x509->sign($issuer, $subject, 'sha256WithRSAEncryption');

        $x509->loadX509($result);
        // https://stackoverflow.com/questions/17355088/how-do-i-set-extkeyusage-with-phpseclib

        if (null !== $me && 0 !== strlen($me)) {
            $x509->setExtension(
                'id-ce-subjectAltName',
                array(
                    array('uniformResourceIdentifier' => $me),
                )
            );
        }
        $x509->setExtension('id-ce-keyUsage', array('digitalSignature', 'keyEncipherment'), true);
        $x509->setExtension('id-ce-extKeyUsage', array('id-kp-clientAuth'));
        $x509->setExtension('id-ce-basicConstraints', array('cA' => false), true);
        $result = $x509->sign($issuer, $x509, 'sha256WithRSAEncryption');

        $format = $saveFormat === self::FORMAT_PEM ? X509::FORMAT_PEM : X509::FORMAT_DER;

        return $x509->saveX509($result, $format);
    }
}
