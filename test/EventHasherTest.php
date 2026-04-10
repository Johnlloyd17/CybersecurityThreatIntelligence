<?php

declare(strict_types=1);

return static function (): void {
    require_once __DIR__ . '/../php/EventHasher.php';
    require_once __DIR__ . '/../php/EventTypes.php';

    $hashA = EventHasher::hash(EventTypes::INTERNET_NAME, 'GMAIL.COM');
    $hashB = EventHasher::hash(EventTypes::INTERNET_NAME, 'gmail.com');
    if ($hashA !== $hashB) {
        throw new RuntimeException('Internet-name hashes should normalize case.');
    }

    $urlA = EventHasher::hash(EventTypes::LINKED_URL_EXTERNAL, 'HTTPS://Example.com/Login');
    $urlB = EventHasher::hash(EventTypes::LINKED_URL_EXTERNAL, 'https://example.com/Login');
    if ($urlA !== $urlB) {
        throw new RuntimeException('URL hashes should normalize scheme and host.');
    }

    $hashC = EventHasher::hash(EventTypes::HASH, 'ABCDEF1234');
    $hashD = EventHasher::hash(EventTypes::HASH, 'abcdef1234');
    if ($hashC !== $hashD) {
        throw new RuntimeException('Hash indicators should normalize case.');
    }
};
