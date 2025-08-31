<?php

namespace WhatsAppStreamEncryption;

use InvalidArgumentException;
use RuntimeException;

class Hkdf
{
    public static function expand(string $key, int $length, string $info = ''): string
    {
        if (strlen($key) < 32) {
            throw new InvalidArgumentException('Key must be at least 32 bytes');
        }

        $hashLength = 32;
        $blocks = ceil($length / $hashLength);
        
        if ($blocks > 255) {
            throw new RuntimeException('Too many blocks');
        }

        $t = '';
        $output = '';

        for ($i = 1; $i <= $blocks; $i++) {
            $t = hash_hmac('sha256', $t . $info . chr($i), $key, true);
            $output .= $t;
        }

        return substr($output, 0, $length);
    }
}