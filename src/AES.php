<?php

namespace Inium\Security\Crypto;

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

        // If cipher method is in openssl_get_cipher_methods(),
        // set params to member variables for using cipher methods.
        if (in_array($cipherMethod, openssl_get_cipher_methods())) {
            $this->_key = $key;
            $this->_cipherMethod = $cipherMethod;
            $this->_useGzCompression = $useGzCompression;
        }
        // Otherwise, throw a exception.
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

            // If gzip compression failed, throw a exception.
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

        // Create hmac for a encrypt text integrity
        // It will use in a decrypt process.
        $hmac = hash_hmac(self::HASH_HMAC_ALGO, $cipherText, $this->_key, true);

        // If hmac creation failed, throw a exception.
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
        // Decode base64 encoded cipher text.
        $cipherText = base64_decode($cipherText);

        // Extract [iv, hmac, cipher_text] elements from a cipher text.
        $elem = $this->extractCipherElements($cipherText);

        // Decrypt cipher text to plain text.
        $plainText = openssl_decrypt($elem['cipher_text'],
                                     $this->_cipherMethod,
                                     $this->_key,
                                     OPENSSL_RAW_DATA,
                                     $elem['iv']);

        // Create a hmac for a verification of cipher text.
        // It will compare to hmac in $elem extracted from a cipher text.
        $hmac = hash_hmac(self::HASH_HMAC_ALGO,
                          $elem['cipher_text'],
                          $this->_key,
                          true);

        // If hmac creation failed, throw a exception.
        if (!$hmac) {
            throw new \Exception('Fail to create hmac from cipher text.');
        }

        // Verification between hmac in cipher text($elem) and created hmac.
        if (!hash_equals($elem['hmac'], $hmac)) {
            throw new \Exception('Fail to decrypt hmac equal comparison.');
        }

        // If use gzcompress, unip.
        if ($this->_useGzCompression) {
            $plainText = gzuncompress($plainText);

            // If unzip failed, throw a exception.
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

        // If IV creation failed, throw a exception.
        if (!$iv) {
            throw new \Exception('Fail to openssl_random_pseudo_bytes().');
        }

        return $iv;
    }

    /**
     * Extract cipher text elements.
     * The cipher text consists of iv, hmac, cipher text.
     *  - "iv" is for use cipher text encryption.
     *  - "hmac" is used for verifying the cipher text is valid or not.
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

        // If one of IV, hmac, cipher text extraction failed, throw a exception.
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
}
