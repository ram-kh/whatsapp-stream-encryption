<?php

use WhatsAppStreamEncryption\StreamCipher;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;
use RuntimeException;

class StreamCipherTest extends TestCase
{
    private const TEST_MEDIA_KEY = '0123456789abcdef0123456789abcdef'; // 32 bytes
    private const TEST_MEDIA_KEY_SHORT = 'short_key';

    // Пути к файлам с примерами
    private const SAMPLES_DIR = __DIR__ . '/../samples/';

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

        // Шифруем
        $encrypted = StreamCipher::encryptStream($testData, self::TEST_MEDIA_KEY, $mediaType);

        $this->assertNotEmpty($encrypted);
        $this->assertNotEquals($testData, $encrypted);
        $this->assertGreaterThan(strlen($testData), strlen($encrypted));

        // Расшифровываем
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

        $wrongKey = 'abcdefghijklmnopqrstuvwxyz012345';

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('MAC validation failed');

        StreamCipher::decryptStream($encrypted, $wrongKey, $mediaType);
    }

    public function testDecryptWithCorruptedData(): void
    {
        $testData = 'Test message';
        $mediaType = 'DOCUMENT';

        $encrypted = StreamCipher::encryptStream($testData, self::TEST_MEDIA_KEY, $mediaType);

        // Изменяем MAC на неправильный
        $corrupted = substr($encrypted, 0, -10) . str_repeat('x', 10);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('MAC validation failed');

        StreamCipher::decryptStream($corrupted, self::TEST_MEDIA_KEY, $mediaType);
    }

    public function testDecryptWithTooShortData(): void
    {
        $shortData = 'too_short';

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid encrypted data');

        StreamCipher::decryptStream($shortData, self::TEST_MEDIA_KEY, 'IMAGE');
    }

    public function testGenerateSidecar(): void
    {
        $testData = str_repeat('Test data for sidecar generation! ', 100);
        $mediaType = 'VIDEO';

        $keys = StreamCipher::expandMediaKey(self::TEST_MEDIA_KEY, $mediaType);
        $macKey = $keys['macKey'];

        $tempFile = tmpfile();
        fwrite($tempFile, $testData);
        rewind($tempFile);

        $sidecar = StreamCipher::generateSidecar($tempFile, $macKey, 64);

        fclose($tempFile);

        $this->assertNotEmpty($sidecar);
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

    public function testDecryptAudioFromSampleFiles(): void
    {
        if (!file_exists(self::SAMPLES_DIR . 'AUDIO.key') || 
            !file_exists(self::SAMPLES_DIR . 'AUDIO.encrypted') ||
            !file_exists(self::SAMPLES_DIR . 'AUDIO.original')) {
            $this->markTestSkipped('Audio sample files not found');
        }

        $mediaKey = file_get_contents(self::SAMPLES_DIR . 'AUDIO.key');
        $encryptedData = file_get_contents(self::SAMPLES_DIR . 'AUDIO.encrypted');
        $expectedData = file_get_contents(self::SAMPLES_DIR . 'AUDIO.original');
        echo $mediaKey;
        $this->assertEquals(32, strlen($mediaKey), 'Media key should be 32 bytes');
        $this->assertGreaterThan(10, strlen($encryptedData), 'Encrypted data should be longer than MAC');

        $decrypted = StreamCipher::decryptStream($encryptedData, $mediaKey, 'AUDIO');

        $this->assertEquals($expectedData, $decrypted, 'Decrypted audio should match original');
    }

    public function testDecryptVideoFromSampleFiles(): void
    {
        if (!file_exists(self::SAMPLES_DIR . 'VIDEO.key') || 
            !file_exists(self::SAMPLES_DIR . 'VIDEO.encrypted') ||
            !file_exists(self::SAMPLES_DIR . 'VIDEO.original')) {
            $this->markTestSkipped('Video sample files not found');
        }

        $mediaKey = file_get_contents(self::SAMPLES_DIR . 'VIDEO.key');
        $encryptedData = file_get_contents(self::SAMPLES_DIR . 'VIDEO.encrypted');
        $expectedData = file_get_contents(self::SAMPLES_DIR . 'VIDEO.original');

        $this->assertEquals(32, strlen($mediaKey), 'Media key should be 32 bytes');

        $decrypted = StreamCipher::decryptStream($encryptedData, $mediaKey, 'VIDEO');

        $this->assertEquals($expectedData, $decrypted, 'Decrypted video should match original');
    }

    public function testDecryptImageFromSampleFiles(): void
    {
        if (!file_exists(self::SAMPLES_DIR . 'IMAGE.key') || 
            !file_exists(self::SAMPLES_DIR . 'IMAGE.encrypted') ||
            !file_exists(self::SAMPLES_DIR . 'IMAGE.original')) {
            $this->markTestSkipped('Image sample files not found');
        }

        $mediaKey = file_get_contents(self::SAMPLES_DIR . 'IMAGE.key');
        $encryptedData = file_get_contents(self::SAMPLES_DIR . 'IMAGE.encrypted');
        $expectedData = file_get_contents(self::SAMPLES_DIR . 'IMAGE.original');

        $this->assertEquals(32, strlen($mediaKey), 'Media key should be 32 bytes');

        $decrypted = StreamCipher::decryptStream($encryptedData, $mediaKey, 'IMAGE');

        $this->assertEquals($expectedData, $decrypted, 'Decrypted image should match original');
    }

    public function testReencryptAudioSample(): void
    {
        if (!file_exists(self::SAMPLES_DIR . 'AUDIO.key') || 
            !file_exists(self::SAMPLES_DIR . 'AUDIO.original')) {
            $this->markTestSkipped('Audio sample files not found');
        }

        $mediaKey = file_get_contents(self::SAMPLES_DIR . 'AUDIO.key');
        $originalData = file_get_contents(self::SAMPLES_DIR . 'AUDIO.original');

        // Re-encrypt with the same key
        $reencrypted = StreamCipher::encryptStream($originalData, $mediaKey, 'AUDIO');
        $decrypted = StreamCipher::decryptStream($reencrypted, $mediaKey, 'AUDIO');

        $this->assertEquals($originalData, $decrypted, 'Re-encrypted audio should decrypt correctly');
    }

    public function testReencryptVideoSample(): void
    {
        if (!file_exists(self::SAMPLES_DIR . 'VIDEO.key') || 
            !file_exists(self::SAMPLES_DIR . 'VIDEO.original')) {
            $this->markTestSkipped('Video sample files not found');
        }

        $mediaKey = file_get_contents(self::SAMPLES_DIR . 'VIDEO.key');
        $originalData = file_get_contents(self::SAMPLES_DIR . 'VIDEO.original');

        $reencrypted = StreamCipher::encryptStream($originalData, $mediaKey, 'VIDEO');
        $decrypted = StreamCipher::decryptStream($reencrypted, $mediaKey, 'VIDEO');

        $this->assertEquals($originalData, $decrypted, 'Re-encrypted video should decrypt correctly');
    }

    public function testSampleFilesIntegrity(): void
    {
        $mediaTypes = ['AUDIO', 'VIDEO', 'IMAGE'];
        
        foreach ($mediaTypes as $mediaType) {
            $keyFile = self::SAMPLES_DIR . $mediaType . '.key';
            $encryptedFile = self::SAMPLES_DIR . $mediaType . '.encrypted';
            $originalFile = self::SAMPLES_DIR . $mediaType . '.original';

            if (!file_exists($keyFile) || !file_exists($encryptedFile) || !file_exists($originalFile)) {
                continue;
            }

            $mediaKey = file_get_contents($keyFile);
            $encryptedData = file_get_contents($encryptedFile);
            $expectedData = file_get_contents($originalFile);

            // Проверяем, что зашифрованные данные имеют правильный MAC
            $this->assertGreaterThan(10, strlen($encryptedData), 
                "Encrypted $mediaType data should contain MAC");

            // Проверяем декрипт
            $decrypted = StreamCipher::decryptStream($encryptedData, $mediaKey, $mediaType);
            $this->assertEquals($expectedData, $decrypted, 
                "Decrypted $mediaType should match original");
        }
    }

    public function testSampleFilesHaveDifferentContent(): void
    {
        $mediaTypes = ['AUDIO', 'VIDEO', 'IMAGE'];
        $contents = [];

        foreach ($mediaTypes as $mediaType) {
            $originalFile = self::SAMPLES_DIR . $mediaType . '.original';
            if (file_exists($originalFile)) {
                $contents[$mediaType] = file_get_contents($originalFile);
            }
        }

        // Проверяем, что все файлы имеют разное содержимое
        $uniqueContents = array_unique($contents);
        $this->assertCount(count($contents), $uniqueContents, 
            'All sample files should have different content');
    }
}