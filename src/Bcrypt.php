<?php

namespace Inium\Security\Crypto;

/**
 * Password encrypt and decrypt using Bcrypt
 */
final class Bcrypt {

    /**
     * Constructor
     */
    public function __construct() {

    }

    /**
     * Get password from plain text.
     *
     * @param string $text  A text which will be encrypted to password.
     * @return string  Encrypted password or false if failed.
     */
    public function hash(string $text): string {
        $hash = password_hash($text, PASSWORD_BCRYPT);
        if (!$hash) {
            throw new \Exception('Bcrypt hash fail.');
        }

        return $hash;
    }

    /**
     * Check if the text matches the password.
     *
     * @param string $text  A text which will be compared with the hash.
     * @param string $hash  A password which will be compaored with the text.
     * @return boolean      true is match, false is otherwise.
     */
    public function verify(string $text, string $hash): bool {
        $ret = password_verify($text, $hash);
        return $ret;
    }
}
