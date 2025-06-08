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
 * Filename: Server/Auth/Store/InMemoryTokenStore.php
 */

 declare(strict_types=1);

 namespace Mcp\Server\Auth\Store;
 
 use Mcp\Server\Auth\TokenStoreInterface;
 
 /**
  * In-memory implementation of token storage.
  * 
  * This implementation stores tokens in memory and is suitable for
  * development, testing, or single-instance deployments. Tokens are
  * lost when the process terminates.
  */
 class InMemoryTokenStore implements TokenStoreInterface
 {
     /**
      * Access tokens storage.
      *
      * @var array<string, array>
      */
     private array $accessTokens = [];
 
     /**
      * Refresh tokens storage.
      *
      * @var array<string, array>
      */
     private array $refreshTokens = [];
 
     /**
      * Authorization codes storage.
      *
      * @var array<string, array>
      */
     private array $authorizationCodes = [];
 
     /**
      * @inheritDoc
      */
     public function storeAccessToken(string $token, array $metadata): void
     {
         $this->accessTokens[$token] = $metadata;
     }
 
     /**
      * @inheritDoc
      */
     public function getAccessToken(string $token): ?array
     {
         if (!isset($this->accessTokens[$token])) {
             return null;
         }
 
         $metadata = $this->accessTokens[$token];
 
         // Check if token is expired
         if (isset($metadata['expires_at']) && $metadata['expires_at'] < time()) {
             $this->deleteAccessToken($token);
             return null;
         }
 
         return $metadata;
     }
 
     /**
      * @inheritDoc
      */
     public function deleteAccessToken(string $token): void
     {
         unset($this->accessTokens[$token]);
     }
 
     /**
      * @inheritDoc
      */
     public function storeRefreshToken(string $token, array $metadata): void
     {
         $this->refreshTokens[$token] = $metadata;
     }
 
     /**
      * @inheritDoc
      */
     public function getRefreshToken(string $token): ?array
     {
         if (!isset($this->refreshTokens[$token])) {
             return null;
         }
 
         $metadata = $this->refreshTokens[$token];
 
         // Check if token is expired
         if (isset($metadata['expires_at']) && $metadata['expires_at'] < time()) {
             $this->deleteRefreshToken($token);
             return null;
         }
 
         return $metadata;
     }
 
     /**
      * @inheritDoc
      */
     public function deleteRefreshToken(string $token): void
     {
         unset($this->refreshTokens[$token]);
     }
 
     /**
      * @inheritDoc
      */
     public function storeAuthorizationCode(string $code, array $metadata): void
     {
         $this->authorizationCodes[$code] = $metadata;
     }
 
     /**
      * @inheritDoc
      */
     public function getAuthorizationCode(string $code): ?array
     {
         if (!isset($this->authorizationCodes[$code])) {
             return null;
         }
 
         $metadata = $this->authorizationCodes[$code];
 
         // Check if code is expired (codes should have short lifetimes, typically 10 minutes)
         if (isset($metadata['expires_at']) && $metadata['expires_at'] < time()) {
             $this->deleteAuthorizationCode($code);
             return null;
         }
 
         return $metadata;
     }
 
     /**
      * @inheritDoc
      */
     public function deleteAuthorizationCode(string $code): void
     {
         unset($this->authorizationCodes[$code]);
     }
 
     /**
      * @inheritDoc
      */
     public function cleanupExpired(): int
     {
         $count = 0;
         $now = time();
 
         // Clean up access tokens
         foreach ($this->accessTokens as $token => $metadata) {
             if (isset($metadata['expires_at']) && $metadata['expires_at'] < $now) {
                 unset($this->accessTokens[$token]);
                 $count++;
             }
         }
 
         // Clean up refresh tokens
         foreach ($this->refreshTokens as $token => $metadata) {
             if (isset($metadata['expires_at']) && $metadata['expires_at'] < $now) {
                 unset($this->refreshTokens[$token]);
                 $count++;
             }
         }
 
         // Clean up authorization codes
         foreach ($this->authorizationCodes as $code => $metadata) {
             if (isset($metadata['expires_at']) && $metadata['expires_at'] < $now) {
                 unset($this->authorizationCodes[$code]);
                 $count++;
             }
         }
 
         return $count;
     }
 
     /**
      * @inheritDoc
      */
     public function getTokensByClient(string $clientId): array
     {
         $tokens = [];
 
         // Get access tokens for client
         foreach ($this->accessTokens as $token => $metadata) {
             if (isset($metadata['client_id']) && $metadata['client_id'] === $clientId) {
                 $tokens[] = array_merge($metadata, [
                     'token' => $token,
                     'type' => 'access_token'
                 ]);
             }
         }
 
         // Get refresh tokens for client
         foreach ($this->refreshTokens as $token => $metadata) {
             if (isset($metadata['client_id']) && $metadata['client_id'] === $clientId) {
                 $tokens[] = array_merge($metadata, [
                     'token' => $token,
                     'type' => 'refresh_token'
                 ]);
             }
         }
 
         return $tokens;
     }
 
     /**
      * @inheritDoc
      */
     public function revokeClientTokens(string $clientId): int
     {
         $count = 0;
 
         // Revoke access tokens
         foreach ($this->accessTokens as $token => $metadata) {
             if (isset($metadata['client_id']) && $metadata['client_id'] === $clientId) {
                 unset($this->accessTokens[$token]);
                 $count++;
             }
         }
 
         // Revoke refresh tokens
         foreach ($this->refreshTokens as $token => $metadata) {
             if (isset($metadata['client_id']) && $metadata['client_id'] === $clientId) {
                 unset($this->refreshTokens[$token]);
                 $count++;
             }
         }
 
         // Revoke authorization codes
         foreach ($this->authorizationCodes as $code => $metadata) {
             if (isset($metadata['client_id']) && $metadata['client_id'] === $clientId) {
                 unset($this->authorizationCodes[$code]);
                 $count++;
             }
         }
 
         return $count;
     }
 
     /**
      * Get current storage statistics.
      *
      * @return array Storage statistics
      */
     public function getStats(): array
     {
         return [
             'access_tokens' => count($this->accessTokens),
             'refresh_tokens' => count($this->refreshTokens),
             'authorization_codes' => count($this->authorizationCodes),
             'total' => count($this->accessTokens) + count($this->refreshTokens) + count($this->authorizationCodes)
         ];
     }
 }