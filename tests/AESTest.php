<?php
declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Inium\Security\Crypto\AES;

/**
 * Test text encrypt and decrypt of Inium\Security\Crypto\AES class
 */
class AESTest extends TestCase {

    /**
     * Test AES encrypt and decrypt methods with data set.
     *
     * @param string $key               AES Key
     * @param string $cipherMethod      AES Method
     * @param boolean $useGzCompression Check if use gzip comporession or not.
     * @param string $plainText         Text will use AES encrypt and decrypt.
     * 
     * @dataProvider additionProvider
     */
    public function testEncryptDecrypt(string $key,
                                       string $cipherMethod,
                                       bool $useGzCompression,
                                       string $plainText) {

        $aes = new AES($key, $cipherMethod, $useGzCompression);

        $cipherText = $aes->encrypt($plainText);
        $decryptedText = $aes->decrypt($cipherText);

        $this->assertSame($plainText, $decryptedText);

        $aes = null;
    }

    /**
     * Data provide to testHashVerify function.
     * - random password from https://randomkeygen.com
     *
     * @return array
     * @see Data Providers, https://phpunit.readthedocs.io/en/9.1/writing-tests-for-phpunit.html#data-providers
     */
    public function additionProvider() {
        // Test cipher methods.
        $cipherMethods = [
            'aes-128-cbc',
            'aes-128-cfb',
            'aes-128-ctr',
            'aes-128-ofb',
            'aes-192-cbc',
            'aes-192-cfb',
            'aes-192-ctr',
            'aes-192-ofb',
            'aes-256-cbc',
            'aes-256-cfb',
            'aes-256-ctr',
            'aes-256-ofb'
        ];


        $plainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $methodCount = count($cipherMethods);

        $testData = [];

        for ($i = 0; $i < $methodCount; $i++) {
            $bit = (int)preg_replace('/[^0-9]/', '', $string);
            $strLen = $bit / 8;
            $useGzCompression = $i / 2 == 0 ? true : false;

            $elem = [
                $this->generateRandomString($strLen),
                $cipherMethods[$i],
                $useGzCompression,
                $plainText
            ];

            array_push($testData, $elem);
        }

        return $testData;
    }

    /**
     * Random string generator
     *
     * @param integer $length   string length.
     *                          - 128bit key length: 16
     *                          - 192bit key length: 24
     *                          - 256bit key length: 32
     * @return string Random string
     * @see https://stackoverflow.com/questions/4356289/php-random-string-generator
     */
    private function generateRandomString($length = 10): string {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);

        $randomString = '';

        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }

        return $randomString;
    }
}
