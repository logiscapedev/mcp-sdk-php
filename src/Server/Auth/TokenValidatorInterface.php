<?php

/**
 * Model Context Protocol SDK for PHP
 *
 * @package    logiscape/mcp-sdk-php
 */

declare(strict_types=1);

namespace Mcp\Server\Auth;

/**
 * Interface for validating access tokens.
 */
interface TokenValidatorInterface
{
    /**
     * Validate the provided token.
     */
    public function validate(string $token): TokenValidationResult;
}
