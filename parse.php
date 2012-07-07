<?php

require 'PHP-Parser/lib/bootstrap.php';

$parser = new PHPParser_Parser(new PHPParser_Lexer);

$code = file_get_contents('php://stdin');

try {
    $statements = $parser->parse($code);
} catch (PHPParser_Error $e) {
    error_log('Parse Error: ' . $e->getMessage());
    exit;
}

$serializer = new PHPParser_Serializer_XML;
echo $serializer->serialize($statements);