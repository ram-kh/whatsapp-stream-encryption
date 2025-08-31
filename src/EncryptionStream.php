<?php

namespace WhatsAppStreamEncryption;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * @property mixed $cipherKey
 */
class EncryptionStream implements StreamInterface
{
    private StreamInterface $stream;
    private string $mediaKey;
    private string $mediaType;
    private string $buffer;
    private int $position;
    private string $cipher;
    private string $iv;
    private string $macKey;
    private bool $eof;

    public function __construct(StreamInterface $stream, string $mediaKey, string $mediaType)
    {
        $this->stream = $stream;
        $this->mediaKey = $mediaKey;
        $this->mediaType = $mediaType;
        $this->position = 0;
        $this->buffer = '';
        $this->eof = false;

        $this->initializeCipher();
    }

    private function initializeCipher(): void
    {
        $keys = StreamCipher::expandMediaKey($this->mediaKey, $this->mediaType);
        $this->iv = $keys['iv'];
        $this->cipherKey = $keys['cipherKey'];
        $this->macKey = $keys['macKey'];

        $this->cipher = openssl_encrypt(
            '',
            'aes-256-cbc',
            $this->cipherKey,
            OPENSSL_RAW_DATA,
            $this->iv
        );
    }

    public function read($length): string
    {
        if ($this->eof) {
            return '';
        }

        $data = $this->stream->read($length);
        
        if ($data === '' && $this->stream->eof()) {
            $this->eof = true;
            $encrypted = openssl_encrypt(
                '',
                'aes-256-cbc',
                $this->cipherKey,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $this->iv
            );
            
            $mac = hash_hmac('sha256', $this->iv . $encrypted, $this->macKey, true);
            $mac = substr($mac, 0, 10);
            
            return $encrypted . $mac;
        }

        $encrypted = openssl_encrypt(
            $data,
            'aes-256-cbc',
            $this->cipherKey,
            OPENSSL_RAW_DATA,
            $this->iv
        );

        $this->position += strlen($encrypted);
        return $encrypted;
    }

    public function __toString(): string
    {
        return $this->getContents();
    }

    public function close(): void
    {
        $this->stream->close();
    }

    public function detach()
    {
        return $this->stream->detach();
    }

    public function getSize(): ?int
    {
        return null;
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->eof;
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        throw new RuntimeException('Stream is not seekable');
    }

    public function rewind(): void
    {
        throw new RuntimeException('Stream is not seekable');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write($string): int
    {
        throw new RuntimeException('Stream is not writable');
    }

    public function getContents(): string
    {
        $result = '';
        while (!$this->eof()) {
            $result .= $this->read(8192);
        }
        return $result;
    }

    public function getMetadata($key = null)
    {
        return $this->stream->getMetadata($key);
    }

    public function isReadable(): void
    {
    }
}