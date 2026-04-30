<?php
require __DIR__ . '/../php/CtiPythonServiceRunner.php';
require __DIR__ . '/../php/SpiderFootModuleMapper.php';
$ref = new ReflectionClass('CtiPythonServiceRunner');
$out = [
  'cti_to_service' => $ref->getReflectionConstant('CTI_TO_SERVICE')->getValue(),
  'module_requires_key' => $ref->getReflectionConstant('MODULE_REQUIRES_KEY')->getValue(),
  'spiderfoot_module_map' => SpiderFootModuleMapper::getModuleMap(),
];
file_put_contents(__DIR__ . '/tmp_maps.json', json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
