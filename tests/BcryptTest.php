<?php
declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Inium\Security\Crypto\Bcrypt;

/**
 * Test hash and verify of Inium\Security\Crypto\Bcrypt class.
 */
final class BcryptTest extends TestCase {

    /**
     * Test hash and verify of Bcrypt class methods with data set.
     *
     * @param string $text  A plain text will use password.
     * 
     * @dataProvider additionProvider
     */
    public function testHashVerify(string $text) {
        $hash = Bcrypt::Hash($text);
        $verified = Bcrypt::Verify($text, $hash);

        $this->assertTrue($verified);
    }

    /**
     * Data provide to testHashVerify function.
     * - random password from https://randomkeygen.com
     *
     * @return array
     * @see Data Providers, https://phpunit.readthedocs.io/en/9.1/writing-tests-for-phpunit.html#data-providers
     */
    public function additionProvider() {
        return [
            'general' => [ 'on!yforTe$t' ],
            'random1' => [ '~c1$ML$21^E_=2k'],
            'random2' => [ 'MiICCFCSDO' ],
            'random3' => [ 'e:xhD#VxRj9x;wt[5^PH98hU4K?zIT' ]
        ];
    }
}
