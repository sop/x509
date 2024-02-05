<?php

declare(strict_types = 1);

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__);

$config = new \PhpCsFixer\Config();
return $config->setRules([
    '@PSR2' => true,
    '@PhpCsFixer' => true,
    'multiline_whitespace_before_semicolons' => [
        'strategy' => 'no_multi_line'
    ],
    'declare_equal_normalize' => [
        'space' => 'single'
    ],
    'method_argument_space' => [
        'on_multiline' => 'ignore'
    ],
    'trailing_comma_in_multiline' => [
        'elements' => []
    ],
    'blank_line_before_statement' => [
        'statements' => []
    ],
    'concat_space' => [
        'spacing' => 'one'
    ],
    'list_syntax' => [
        'syntax' => 'short'
    ],
    'echo_tag_syntax' => [
        'format' => 'short'
    ],
    'no_alternative_syntax' => false,
    'php_unit_test_class_requires_covers' => false,
    'phpdoc_to_comment' => false,
    'phpdoc_var_without_name' => false,
])
    ->setFinder($finder);
