<?php

declare(strict_types=1);

return static function (): void {
    require_once __DIR__ . '/../php/ScanEvent.php';
    require_once __DIR__ . '/../php/EventTypes.php';

    $root = ScanEvent::root(42, 'domain', 'gmail.com');
    if ($root->eventType !== EventTypes::ROOT) {
        throw new RuntimeException('Root event type mismatch.');
    }

    $seed = ScanEvent::seedTarget(42, 'domain', 'gmail.com', $root->eventHash);
    if ($seed->eventType !== EventTypes::INTERNET_NAME) {
        throw new RuntimeException('Seed event should map domain -> Internet Name.');
    }
    if ($seed->parentEventHash !== $root->eventHash) {
        throw new RuntimeException('Seed event should point back to the root event.');
    }

    $child = ScanEvent::discovery(
        42,
        EventTypes::IP_ADDRESS,
        '8.8.8.8',
        'virustotal',
        $seed->eventHash,
        $seed->data,
        1,
        ['note' => 'test'],
        90,
        25
    );

    if ($child->depth !== 1) {
        throw new RuntimeException('Discovery depth should be preserved.');
    }
    if ($child->sourceData !== 'gmail.com') {
        throw new RuntimeException('Discovery source data should preserve the parent event data.');
    }
    if ($child->eventHash === '') {
        throw new RuntimeException('Discovery event should have a hash.');
    }
};
