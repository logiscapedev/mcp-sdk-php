<?php

/**
 * Model Context Protocol SDK for PHP
 *
 * (c) 2025 Logiscape LLC <https://logiscape.com>
 *
 * Developed by:
 * - Josh Abbott
 * - Claude Opus 4 (Anthropic AI model)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @package    logiscape/mcp-sdk-php 
 * @author     Josh Abbott <https://joshabbott.com>
 * @copyright  Logiscape LLC
 * @license    MIT License
 * @link       https://github.com/logiscape/mcp-sdk-php
 *
 * Filename: Server/Auth/Utils/TokenGenerator.php
 */

 declare(strict_types=1);

 namespace Mcp\Server\Auth\Utils;
 
 /**
  * Utility class for generating secure OAuth tokens.
  * 
  * This class provides methods for generating cryptographically secure
  * tokens for access tokens, refresh tokens, authorization codes, and
  * client credentials.
  */
 class TokenGenerator
 {
     /**
      * Default token length in bytes.
      */
     private const DEFAULT_TOKEN_LENGTH = 32;
 
     /**
      * Default client ID length in bytes.
      */
     private const CLIENT_ID_LENGTH = 16;
 
     /**
      * Default client secret length in bytes.
      */
     private const CLIENT_SECRET_LENGTH = 32;
 
     /**
      * Authorization code length in bytes.
      */
     private const AUTH_CODE_LENGTH = 16;
 
     /**
      * Generate a secure access token.
      *
      * @param int|null $length Token length in bytes (default: 32)
      * @return string Base64url-encoded token
      */
     public static function generateAccessToken(?int $length = null): string
     {
         $length = $length ?? self::DEFAULT_TOKEN_LENGTH;
         return self::generateToken($length);
     }
 
     /**
      * Generate a secure refresh token.
      *
      * @param int|null $length Token length in bytes (default: 32)
      * @return string Base64url-encoded token
      */
     public static function generateRefreshToken(?int $length = null): string
     {
         $length = $length ?? self::DEFAULT_TOKEN_LENGTH;
         return self::generateToken($length);
     }
 
     /**
      * Generate a secure authorization code.
      *
      * @return string Base64url-encoded code
      */
     public static function generateAuthorizationCode(): string
     {
         return self::generateToken(self::AUTH_CODE_LENGTH);
     }
 
     /**
      * Generate a client ID.
      *
      * @return string Base64url-encoded client ID
      */
     public static function generateClientId(): string
     {
         return self::generateToken(self::CLIENT_ID_LENGTH);
     }
 
     /**
      * Generate a client secret.
      *
      * @return string Base64url-encoded client secret
      */
     public static function generateClientSecret(): string
     {
         return self::generateToken(self::CLIENT_SECRET_LENGTH);
     }
 
     /**
      * Generate a registration access token.
      *
      * @return string Base64url-encoded token
      */
     public static function generateRegistrationToken(): string
     {
         return self::generateToken(self::DEFAULT_TOKEN_LENGTH);
     }
 
     /**
      * Generate a state parameter for OAuth flows.
      *
      * @return string Base64url-encoded state
      */
     public static function generateState(): string
     {
         return self::generateToken(16);
     }
 
     /**
      * Generate a nonce.
      *
      * @return string Base64url-encoded nonce
      */
     public static function generateNonce(): string
     {
         return self::generateToken(16);
     }
 
     /**
      * Generate a secure random token.
      *
      * @param int $length Token length in bytes
      * @return string Base64url-encoded token
      * @throws \Exception If random bytes generation fails
      */
     private static function generateToken(int $length): string
     {
         $bytes = random_bytes($length);
         return self::base64UrlEncode($bytes);
     }
 
     /**
      * Base64url encode a string.
      *
      * @param string $data Data to encode
      * @return string Base64url-encoded string
      */
     public static function base64UrlEncode(string $data): string
     {
         return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
     }
 
     /**
      * Base64url decode a string.
      *
      * @param string $data Data to decode
      * @return string Decoded string
      */
     public static function base64UrlDecode(string $data): string
     {
         return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
     }
 
     /**
      * Generate a code verifier for PKCE.
      *
      * @return string Code verifier (43-128 characters)
      */
     public static function generateCodeVerifier(): string
     {
         // Generate 32 bytes (will be 43 characters after base64url encoding)
         return self::generateToken(32);
     }
 
     /**
      * Generate a code challenge from a code verifier.
      *
      * @param string $verifier Code verifier
      * @param string $method Challenge method (default: S256)
      * @return string Code challenge
      * @throws \InvalidArgumentException If method is not supported
      */
     public static function generateCodeChallenge(string $verifier, string $method = 'S256'): string
     {
         if ($method === 'plain') {
             return $verifier;
         }
 
         if ($method === 'S256') {
             $hash = hash('sha256', $verifier, true);
             return self::base64UrlEncode($hash);
         }
 
         throw new \InvalidArgumentException("Unsupported PKCE method: {$method}");
     }
 
     /**
      * Verify a code challenge against a verifier.
      *
      * @param string $verifier Code verifier
      * @param string $challenge Code challenge
      * @param string $method Challenge method
      * @return bool True if valid
      */
     public static function verifyCodeChallenge(string $verifier, string $challenge, string $method = 'S256'): bool
     {
         try {
             $expectedChallenge = self::generateCodeChallenge($verifier, $method);
             return hash_equals($expectedChallenge, $challenge);
         } catch (\InvalidArgumentException $e) {
             return false;
         }
     }
 
     /**
      * Generate a unique token ID (jti) for JWT tokens.
      *
      * @return string Token ID
      */
     public static function generateTokenId(): string
     {
         return self::generateToken(16);
     }
 
     /**
      * Generate an expiration timestamp.
      *
      * @param int $lifetime Lifetime in seconds
      * @return int Unix timestamp
      */
     public static function generateExpiration(int $lifetime): int
     {
         return time() + $lifetime;
     }
 
     /**
      * Check if a timestamp has expired.
      *
      * @param int $timestamp Unix timestamp
      * @return bool True if expired
      */
     public static function isExpired(int $timestamp): bool
     {
         return time() > $timestamp;
     }
 
     /**
      * Generate a secure hash of a token for storage.
      *
      * @param string $token Token to hash
      * @return string Hashed token
      */
     public static function hashToken(string $token): string
     {
         return hash('sha256', $token);
     }
 
     /**
      * Generate a bearer token string.
      *
      * @param string $token Access token
      * @return string Bearer token string
      */
     public static function formatBearerToken(string $token): string
     {
         return 'Bearer ' . $token;
     }
 
     /**
      * Extract token from Bearer authorization header.
      *
      * @param string $header Authorization header value
      * @return string|null Token or null if not a valid Bearer token
      */
     public static function extractBearerToken(string $header): ?string
     {
         if (preg_match('/^Bearer\s+(.+)$/i', $header, $matches)) {
             return $matches[1];
         }
         return null;
     }
 }