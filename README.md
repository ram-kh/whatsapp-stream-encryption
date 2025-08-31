Использование
---

```
use WhatsAppStreamEncryption\EncryptionStream;
use WhatsAppStreamEncryption\DecryptionStream;
use GuzzleHttp\Psr7\Stream;

// Шифрование
$inputStream = new Stream(fopen('input.jpg', 'r'));
$mediaKey = random_bytes(32); // или существующий ключ
$encryptedStream = new EncryptionStream($inputStream, $mediaKey, 'IMAGE');

// Дешифрование  
$encryptedStream = new Stream(fopen('encrypted.jpg', 'r'));
$decryptedStream = new DecryptionStream($encryptedStream, $mediaKey, 'IMAGE');

// Генерация sidecar для стриминга
$sidecar = StreamCipher::generateSidecar($decryptedStream, $macKey);
```