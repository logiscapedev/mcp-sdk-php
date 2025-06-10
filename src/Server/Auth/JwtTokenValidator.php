<?php

/**
 * Model Context Protocol SDK for PHP
 *
 * @package    logiscape/mcp-sdk-php
 */

declare(strict_types=1);

namespace Mcp\Server\Auth;

/**
 * Basic JWT validator supporting HS256 and RS256 algorithms.
 */
class JwtTokenValidator implements TokenValidatorInterface
{
    public function __construct(
        private readonly string $key,
        private readonly string $algorithm = 'HS256'
    ) {
    }

    public function validate(string $token): TokenValidationResult
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return new TokenValidationResult(false, [], 'Malformed token');
        }

        [$encodedHeader, $encodedPayload, $encodedSig] = $parts;
        $header = json_decode($this->base64UrlDecode($encodedHeader), true);
        $payload = json_decode($this->base64UrlDecode($encodedPayload), true);
        if ($header === null || $payload === null) {
            return new TokenValidationResult(false, [], 'Invalid encoding');
        }

        $alg = $header['alg'] ?? $this->algorithm;
        $data = $encodedHeader . '.' . $encodedPayload;
        $signature = $this->base64UrlDecode($encodedSig);

        $valid = false;
        if ($alg === 'HS256') {
            $expected = hash_hmac('sha256', $data, $this->key, true);
            $valid = hash_equals($expected, $signature);
        } elseif ($alg === 'RS256') {
            $valid = openssl_verify($data, $signature, $this->key, OPENSSL_ALGO_SHA256) === 1;
        } else {
            return new TokenValidationResult(false, [], 'Unsupported algorithm');
        }

        return new TokenValidationResult($valid, $valid ? $payload : [], $valid ? null : 'Signature verification failed');
    }

    private function base64UrlDecode(string $input): string
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($input, '-_', '+/')) ?: '';
    }
}
