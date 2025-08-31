<?php

use WhatsAppStreamEncryption\StreamCipher;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;
use RuntimeException;

class StreamCipherTest extends TestCase
{
    private const TEST_MEDIA_KEY = '0123456789abcdef0123456789abcdef'; // 32 bytes
    private const TEST_MEDIA_KEY_SHORT = 'short_key'; // Too short

    public function testExpandMediaKeyWithValidKey(): void
    {
        $keys = StreamCipher::expandMediaKey(self::TEST_MEDIA_KEY, 'IMAGE');

        $this->assertIsArray($keys);
        $this->assertArrayHasKey('iv', $keys);
        $this->assertArrayHasKey('cipherKey', $keys);
        $this->assertArrayHasKey('macKey', $keys);
        $this->assertArrayHasKey('refKey', $keys);

        $this->assertEquals(16, strlen($keys['iv']));
        $this->assertEquals(32, strlen($keys['cipherKey']));
        $this->assertEquals(32, strlen($keys['macKey']));
        $this->assertEquals(32, strlen($keys['refKey']));
    }

    public function testExpandMediaKeyWithInvalidKeyLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be at least 32 bytes');

        StreamCipher::expandMediaKey(self::TEST_MEDIA_KEY_SHORT, 'IMAGE');
    }

    public function testExpandMediaKeyWithUnknownMediaType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown media type: UNKNOWN_TYPE');

        StreamCipher::expandMediaKey(self::TEST_MEDIA_KEY, 'UNKNOWN_TYPE');
    }

    public function testEncryptAndDecryptStream(): void
    {
        $testData = 'Hello, this is a test message for encryption!';
        $mediaType = 'DOCUMENT';

        // Encrypt
        $encrypted = StreamCipher::encryptStream($testData, self::TEST_MEDIA_KEY, $mediaType);

        $this->assertNotEmpty($encrypted);
        $this->assertNotEquals($testData, $encrypted);
        $this->assertGreaterThan(strlen($testData), strlen($encrypted)); // Due to padding and MAC

        // Decrypt
        $decrypted = StreamCipher::decryptStream($encrypted, self::TEST_MEDIA_KEY, $mediaType);

        $this->assertEquals($testData, $decrypted);
    }

    public function testEncryptAndDecryptEmptyStream(): void
    {
        $testData = '';
        $mediaType = 'AUDIO';

        $encrypted = StreamCipher::encryptStream($testData, self::TEST_MEDIA_KEY, $mediaType);
        $decrypted = StreamCipher::decryptStream($encrypted, self::TEST_MEDIA_KEY, $mediaType);

        $this->assertEquals($testData, $decrypted);
    }

    public function testEncryptAndDecryptLargeData(): void
    {
        $testData = str_repeat('Testing encryption and decryption! ', 1000);
        $mediaType = 'VIDEO';

        $encrypted = StreamCipher::encryptStream($testData, self::TEST_MEDIA_KEY, $mediaType);
        $decrypted = StreamCipher::decryptStream($encrypted, self::TEST_MEDIA_KEY, $mediaType);

        $this->assertEquals($testData, $decrypted);
    }

    public function testDecryptWithWrongKey(): void
    {
        $testData = 'Test message';
        $mediaType = 'IMAGE';

        $encrypted = StreamCipher::encryptStream($testData, self::TEST_MEDIA_KEY, $mediaType);

        $wrongKey = 'abcdefghijklmnopqrstuvwxyz012345'; // Different 32-byte key

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('MAC validation failed');

        StreamCipher::decryptStream($encrypted, $wrongKey, $mediaType);
    }

    public function testDecryptWithCorruptedData(): void
    {
        $testData = 'Test message';
        $mediaType = 'DOCUMENT';

        $encrypted = StreamCipher::encryptStream($testData, self::TEST_MEDIA_KEY, $mediaType);

        // Corrupt the MAC
        $corrupted = substr($encrypted, 0, -10) . str_repeat('x', 10);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('MAC validation failed');

        StreamCipher::decryptStream($corrupted, self::TEST_MEDIA_KEY, $mediaType);
    }

    public function testDecryptWithTooShortData(): void
    {
        $shortData = 'too_short'; // Less than 10 bytes (MAC length)

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid encrypted data');

        StreamCipher::decryptStream($shortData, self::TEST_MEDIA_KEY, 'IMAGE');
    }

    public function testDifferentMediaTypesProduceDifferentKeys(): void
    {
        $keysImage = StreamCipher::expandMediaKey(self::TEST_MEDIA_KEY, 'IMAGE');
        $keysVideo = StreamCipher::expandMediaKey(self::TEST_MEDIA_KEY, 'VIDEO');
        $keysAudio = StreamCipher::expandMediaKey(self::TEST_MEDIA_KEY, 'AUDIO');
        $keysDocument = StreamCipher::expandMediaKey(self::TEST_MEDIA_KEY, 'DOCUMENT');

        // All should be different due to different application info
        $this->assertNotEquals($keysImage['iv'], $keysVideo['iv']);
        $this->assertNotEquals($keysImage['cipherKey'], $keysAudio['cipherKey']);
        $this->assertNotEquals($keysVideo['macKey'], $keysDocument['macKey']);
    }

    public function testGenerateSidecar(): void
    {
        $testData = str_repeat('Test data for sidecar generation! ', 100);
        $mediaType = 'VIDEO';

        $keys = StreamCipher::expandMediaKey(self::TEST_MEDIA_KEY, $mediaType);
        $macKey = $keys['macKey'];

        // Create temporary stream
        $tempFile = tmpfile();
        fwrite($tempFile, $testData);
        rewind($tempFile);

        $sidecar = StreamCipher::generateSidecar($tempFile, $macKey, 64); // Small chunk size for testing

        fclose($tempFile);

        $this->assertNotEmpty($sidecar);
        // Sidecar should contain multiple 10-byte MAC chunks
        $this->assertEquals(0, strlen($sidecar) % 10);
        $this->assertGreaterThan(0, strlen($sidecar) / 10);
    }

    public function testGenerateSidecarWithEmptyStream(): void
    {
        $mediaType = 'AUDIO';

        $keys = StreamCipher::expandMediaKey(self::TEST_MEDIA_KEY, $mediaType);
        $macKey = $keys['macKey'];

        $emptyStream = fopen('php://memory', 'r');
        $sidecar = StreamCipher::generateSidecar($emptyStream, $macKey);

        fclose($emptyStream);

        $this->assertEmpty($sidecar);
    }

    public function testMediaTypeConstants(): void
    {
        $mediaTypes = StreamCipher::MEDIA_TYPES;

        $this->assertArrayHasKey('IMAGE', $mediaTypes);
        $this->assertArrayHasKey('VIDEO', $mediaTypes);
        $this->assertArrayHasKey('AUDIO', $mediaTypes);
        $this->assertArrayHasKey('DOCUMENT', $mediaTypes);

        $this->assertEquals('WhatsApp Image Keys', $mediaTypes['IMAGE']);
        $this->assertEquals('WhatsApp Video Keys', $mediaTypes['VIDEO']);
        $this->assertEquals('WhatsApp Audio Keys', $mediaTypes['AUDIO']);
        $this->assertEquals('WhatsApp Document Keys', $mediaTypes['DOCUMENT']);
    }
}