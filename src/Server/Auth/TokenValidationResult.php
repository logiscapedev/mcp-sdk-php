<?php

/**
 * Model Context Protocol SDK for PHP
 *
 * @package    logiscape/mcp-sdk-php
 */

declare(strict_types=1);

namespace Mcp\Server\Auth;

/**
 * Result of a token validation attempt.
 */
class TokenValidationResult
{
    /**
     * Constructor.
     *
     * @param bool $valid Whether the token was valid
     * @param array<string,mixed> $claims Token claims if valid
     * @param string|null $error Optional validation error message
     */
    public function __construct(
        public readonly bool $valid,
        public readonly array $claims = [],
        public readonly ?string $error = null
    ) {
    }
}
