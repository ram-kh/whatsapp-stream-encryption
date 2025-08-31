<?php

namespace WhatsAppStreamEncryption;

use Exception;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

class DecryptionStream implements StreamInterface
{
    private $stream;
    private $mediaKey;
    private $mediaType;
    private $buffer;
    private $position;
    private $cipherKey;
    private $iv;
    private $macKey;
    private $eof;

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
    }

    public function read($length): string
    {
        if ($this->eof) {
            return '';
        }

        $encrypted = $this->stream->read($length);
        
        if ($encrypted === '' && $this->stream->eof()) {
            $this->eof = true;
            
            // Handle final block and verify MAC
            if (strlen($this->buffer) < 10) {
                throw new RuntimeException('Invalid encrypted data');
            }

            $file = substr($this->buffer, 0, -10);
            $mac = substr($this->buffer, -10);

            // Verify MAC
            $calculatedMac = hash_hmac('sha256', $this->iv . $file, $this->macKey, true);
            $calculatedMac = substr($calculatedMac, 0, 10);

            if (!hash_equals($calculatedMac, $mac)) {
                throw new RuntimeException('MAC validation failed');
            }

            // Decrypt final block
            $decrypted = openssl_decrypt(
                $file,
                'aes-256-cbc',
                $this->cipherKey,
                OPENSSL_RAW_DATA,
                $this->iv
            );

            $this->position += strlen($decrypted);
            return $decrypted;
        }

        $this->buffer .= $encrypted;

        $blockSize = 16;
        $decryptableLength = floor(strlen($this->buffer) / $blockSize) * $blockSize;
        
        if ($decryptableLength > 0) {
            $toDecrypt = substr($this->buffer, 0, $decryptableLength);
            $this->buffer = substr($this->buffer, $decryptableLength);

            $decrypted = openssl_decrypt(
                $toDecrypt,
                'aes-256-cbc',
                $this->cipherKey,
                OPENSSL_RAW_DATA,
                $this->iv
            );

            $this->position += strlen($decrypted);
            return $decrypted;
        }

        return '';
    }

    public function __toString(): string
    {
        return $this->getContents();
    }

    public function write($data)
    {
        throw new Exception('DecryptionStream is read-only');
    }

    public function close(): void
    {
        $this->stream->close();
        openssl_free_key($this->cipher);
    }

    public function detach(): ?StreamInterface
    {
        throw new Exception('DecryptionStream does not support detaching');
    }

    public function getMetadata($key = null)
    {
        return $this->stream->getMetadata($key);
    }

    /**
     * @param $offset
     * @param $whence
     * @return mixed
     */
    public function seek($offset, $whence = SEEK_SET)
    {
        throw new Exception('DecryptionStream does not support seeking');
    }

    public function tell(): void
    {
        throw new Exception('DecryptionStream does not support tell');
    }

    public function eof(): bool
    {
        return $this->eof && empty($this->buffer);
    }

    public function getSize()
    {
        return null;
    }

    public function isSeekable()
    {
        // TODO: Implement isSeekable() method.
    }

    public function rewind()
    {
        // TODO: Implement rewind() method.
    }

    public function isWritable()
    {
        // TODO: Implement isWritable() method.
    }

    public function isReadable()
    {
        // TODO: Implement isReadable() method.
    }

    public function getContents()
    {
        // TODO: Implement getContents() method.
    }
}