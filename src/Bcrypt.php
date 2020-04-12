<?php

namespace Inium\Security\Crypto;

/**
 * Password encrypt and decrypt using Bcrypt
 */
final class Bcrypt {

    /**
     * Get password from plain text.
     *
     * @param string $text  A text which will be encrypted to password.
     * @return string|bool  Encrypted password or false if failed.
     */
    public static function hash(string $text) {
        $ret = password_hash($text, PASSWORD_BCRYPT);
        return $ret;
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
