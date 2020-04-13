<?php

namespace Inium\Security\Crypto;

/**
 * AES encryption / decryption.
 */
final class AES {

    /**
     * AES Encryption Key
     *
     * @var string
     */
    private $_key = null;

    /**
     * AES Method
     *
     * @var string
     * @see openssl_get_cipher_methods()
     */
    private $_cipherMethod = null;

    /**
     * Check if gzcompress() use or not
     *
     * @var boolean
     */
    private $_useGzCompression = false;

    /**
     * hash_hmac algorithm
     * 
     * @var string
     */
    const HASH_HMAC_ALGO = 'sha256';

    /**
     * SHA256 length for hash_hmac
     * 
     * @var integer
     */
    const SHA2_LENGTH = 32;


    /**
     * Constructor
     *
     * @param string $key               AES Encryption Key
     * @param string $cipherMethod      AES method. Default is "aes-256-cbc".
     *                                  - see openssl_get_cipher_methods()
     * @param boolean $useGzCompress    Check if gzcompress() use or not.
     *                                  Default is false.
     */
    public function __construct(string $key,
                                string $cipherMethod = 'aes-256-cbc',
                                bool $useGzCompression = false) {

        // If $cipherMethod param is valid, set params to members.
        if (in_array($cipherMethod, openssl_get_cipher_methods())) {
            $this->_key = $key;
            $this->_cipherMethod = $cipherMethod;
            $this->_useGzCompression = $useGzCompression;
        }
        // Else throw a exception.
        else {
            throw new \Exception('Invalid cipher method.');
        }
    }

    /**
     * Encrypt plain text to cipher text.
     *
     * @param string $plainText     Plain text will use to AES encryption.
     * @return string               Cipher Text to "iv.hmac.cipherText".
     * @see https://www.php.net/manual/en/function.openssl-encrypt.php
     */
    public function encrypt(string $plainText): string {
        // Get random iv for encryption.
        $iv = $this->getRandomIV();

        // If use gzip compression.
        if ($this->_useGzCompression) {
            $plainText = gzcompress($plainText);
            if (!$plainText) {
                throw new \Exception('Fail to gzcompress.');
            }
        }

        // Encrypt plain text.
        $cipherText = openssl_encrypt($plainText,
                                      $this->_cipherMethod,
                                      $this->_key,
                                      OPENSSL_RAW_DATA,
                                      $iv);

        // Create hmac for a encrypt text integrity it will use decrypt process.
        $hmac = hash_hmac(self::HASH_HMAC_ALGO, $cipherText, $this->_key, true);
        if (!$hmac) {
            throw new \Exception('Fail to create hmac.');
        }

        // base64 encode
        $base64 = base64_encode($iv.$hmac.$cipherText);
        return $base64;
    }

    /**
     * Decrypt cipher text to plain text.
     *
     * @param string $cipherText    Cipher text will use to AES decryption.
     * @return string               Plain text.
     * @see https://www.php.net/manual/en/function.openssl-encrypt.php
     */
    public function decrypt(string $cipherText): string {
        // base64 decode
        $cipherText = base64_decode($cipherText);

        // Extract [iv, hmac, cipher_text] elements from a cipher text.
        $elem = $this->extractCipherElements($cipherText);

        // Decrypt cipher_text in $elem.
        $plainText = openssl_decrypt($elem['cipher_text'],
                                     $this->_cipherMethod,
                                     $this->_key,
                                     OPENSSL_RAW_DATA,
                                     $elem['iv']);

        // Check integrity
        $integrity = $this->checkIntegrity($elem['cipher_text'], $elem['hmac']);
        if (!$integrity) {
            throw new \Exception('Fail to integrity test.');
        }

        // If use gzcompress, unip.
        if ($this->_useGzCompression) {
            $plainText = gzuncompress($plainText);
            if (!$plainText) {
                throw new \Exception('Fail to gzuncompress.');
            }
        }

        return $plainText;
    }

    /**
     * Get Random IV(Initialization Vector)
     *
     * @return string   IV of the AES Method.
     * @return string   IV
     */
    private function getRandomIV(): string {
        $ivlen = openssl_cipher_iv_length($this->_cipherMethod);
        $iv = openssl_random_pseudo_bytes($ivlen);

        if (!$iv) {
            throw new \Exception('Fail to openssl_random_pseudo_bytes().');
        }

        return $iv;
    }

    /**
     * Extract cipher text elements.
     * The cipher text consists of iv, hmac, cipher text.
     *  - "iv" s used for the cipher text encryption.
     *  - "hmac" is used for checking the cipher text integrity when decryption.
     *  - "cipher text" is a encrypted text.
     *
     * @param string $cipherText    Cipher text.
     * @return array                [iv, hmac, cipher_text].
     */
    private function extractCipherElements(string $cipherText): array {
        $ivLen = openssl_cipher_iv_length($this->_cipherMethod);

        $iv = substr($cipherText, 0, $ivLen);
        $hmac = substr($cipherText, $ivLen, self::SHA2_LENGTH);
        $cipherText = substr($cipherText, $ivLen + self::SHA2_LENGTH);

        if (!$iv || !$hmac || !$cipherText) {
            throw new \Exception('Fail to extract cipher elements.');
        }

        $elem = [
            'iv'          => $iv,
            'hmac'        => $hmac,
            'cipher_text' => $cipherText
        ];

        return $elem;
    }

    /**
     * Check the cipher text has integrity (valid) or not.
     *
     * @param string $cipherText
     * @param string $hmac
     * @return boolean
     */
    private function checkIntegrity(string $cipherText, string $hmac): bool {
        // Create a hmac from a $cipherText for a integrity check in below.
        $calcHmac = hash_hmac(self::HASH_HMAC_ALGO,
                              $cipherText,
                              $this->_key,
                              true);
        if (!$calcHmac) {
            throw new \Exception('Fail to create hmac from cipher text.');
        }

        // Do verification between $calcHmac and $hmac.
        // If equal, the cipher text has integrity.
        $ret = hash_equals($hmac, $calcHmac);

        return $ret;
    }
}
