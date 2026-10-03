<?php
if ($argc < 2) {
    fwrite(STDERR, "Usage: php rips-wrapper.php <target>\n");
    exit(2);
}

$target = realpath($argv[1]);
if ($target === false) {
    fwrite(STDERR, "Target does not exist: {$argv[1]}\n");
    exit(2);
}

$_POST = [
    'loc' => $target,
    'subdirs' => '1',
    'ignore_warning' => '1',
    'verbosity' => '2',
    'vector' => 'server',
];
$_SERVER['DOCUMENT_ROOT'] = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rips';

$originalDirectory = getcwd();
chdir(__DIR__ . DIRECTORY_SEPARATOR . 'rips');
ob_start();
try {
    include 'main.php';
    ob_end_clean();
} catch (Throwable $error) {
    ob_end_clean();
    fwrite(STDERR, "RIPS execution failed: {$error->getMessage()}\n");
    exit(1);
} finally {
    chdir($originalDirectory);
}

$findings = [];
foreach (($GLOBALS['output'] ?? []) as $file => $blocks) {
    if (!is_array($blocks)) continue;
    foreach ($blocks as $block) {
        if (!is_object($block) || empty($block->vuln) || empty($block->treenodes)) continue;
        foreach ($block->treenodes as $node) {
            if (!is_object($node)) continue;
            $nodeFile = $node->filename ?: $file;
            $line = isset($node->lines[0]) ? (int)$node->lines[0] : 1;
            $title = trim((string)($node->title ?: $block->category ?: 'RIPS finding'));
            $sink = trim((string)($block->sink ?? ''));
            $findings[] = [
                'ruleId' => strtolower(preg_replace('/[^a-z0-9]+/i', '-', $block->category ?: $sink ?: 'finding')),
                'message' => $title,
                'severity' => 'high',
                'confidence' => 'medium',
                'category' => 'security',
                'file' => $nodeFile,
                'line' => max(1, $line),
                'column' => 1,
                'evidence' => trim(strip_tags((string)($node->value ?? ''))),
                'suggestion' => 'Review the taint trace and validate or sanitize untrusted input before the sensitive sink.',
                'references' => [],
            ];
        }
    }
}

echo json_encode(['findings' => $findings], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
