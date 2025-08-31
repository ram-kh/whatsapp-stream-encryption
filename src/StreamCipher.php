<?php

namespace WhatsAppStreamEncryption;

use InvalidArgumentException;
use RuntimeException;

class StreamCipher
{
    public const MEDIA_TYPES = [
        'IMAGE' => 'WhatsApp Image Keys',
        'VIDEO' => 'WhatsApp Video Keys',
        'AUDIO' => 'WhatsApp Audio Keys',
        'DOCUMENT' => 'WhatsApp Document Keys',
    ];


    public static function expandMediaKey(string $mediaKey, string $mediaType): array
    {
        if (!isset(self::MEDIA_TYPES[$mediaType])) {
            throw new InvalidArgumentException("Unknown media type: $mediaType");
        }

        if (strlen($mediaKey) !== 32) {
            throw new InvalidArgumentException('Media key must be 32 bytes');
        }

        $info = self::MEDIA_TYPES[$mediaType];
        $mediaKeyExpanded = Hkdf::expand($mediaKey, 112, $info);

        return [
            'iv' => substr($mediaKeyExpanded, 0, 16),
            'cipherKey' => substr($mediaKeyExpanded, 16, 32),
            'macKey' => substr($mediaKeyExpanded, 48, 32),
            'refKey' => substr($mediaKeyExpanded, 80, 32)
        ];
    }

    public static function encryptStream($input, string $mediaKey, string $mediaType): string
    {
        $keys = self::expandMediaKey($mediaKey, $mediaType);
        
        $iv = $keys['iv'];
        $cipherKey = $keys['cipherKey'];
        $macKey = $keys['macKey'];

        $cipher = openssl_encrypt(
            $input,
            'aes-256-cbc',
            $cipherKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($cipher === false) {
            throw new RuntimeException('Encryption failed');
        }

        $mac = hash_hmac('sha256', $iv . $cipher, $macKey, true);
        $mac = substr($mac, 0, 10);

        return $cipher . $mac;
    }

    public static function decryptStream($input, string $mediaKey, string $mediaType): string
    {
        $keys = self::expandMediaKey($mediaKey, $mediaType);
        
        $iv = $keys['iv'];
        $cipherKey = $keys['cipherKey'];
        $macKey = $keys['macKey'];

        $file = substr($input, 0, -10);
        $mac = substr($input, -10);

        $calculatedMac = hash_hmac('sha256', $iv . $file, $macKey, true);
        $calculatedMac = substr($calculatedMac, 0, 10);

        if (!hash_equals($calculatedMac, $mac)) {
            throw new RuntimeException('MAC validation failed');
        }

        $decrypted = openssl_decrypt(
            $file,
            'aes-256-cbc',
            $cipherKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($decrypted === false) {
            throw new RuntimeException('Decryption failed');
        }

        return $decrypted;
    }

    public static function generateSidecar($stream, string $macKey, int $chunkSize = 65536): string
    {
        $sidecar = '';
        $chunkNumber = 0;

        while (!feof($stream)) {
            $chunk = fread($stream, $chunkSize);
            if ($chunk === false) {
                break;
            }

            // For video/audio: sign [n*64K, (n+1)*64K+16]
            $mac = hash_hmac('sha256', $chunk, $macKey, true);
            $sidecar .= substr($mac, 0, 10);
            
            $chunkNumber++;
        }

        return $sidecar;
    }
}