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
 * Filename: Server/Auth/TokenManager.php
 */

 declare(strict_types=1);

 namespace Mcp\Server\Auth;
 
 use Mcp\Server\Auth\Utils\TokenGenerator;
 use Psr\Log\LoggerInterface;
 use Psr\Log\NullLogger;
 
 /**
  * Manages OAuth tokens for MCP servers.
  * 
  * This class handles the creation, validation, storage, and lifecycle
  * management of access tokens, refresh tokens, and authorization codes.
  */
 class TokenManager
 {
     /**
      * Token store instance.
      *
      * @var TokenStoreInterface
      */
     private TokenStoreInterface $tokenStore;
 
     /**
      * Authorization configuration.
      *
      * @var AuthorizationConfig
      */
     private AuthorizationConfig $config;
 
     /**
      * Logger instance.
      *
      * @var LoggerInterface
      */
     private LoggerInterface $logger;
 
     /**
      * Constructor.
      *
      * @param AuthorizationConfig $config Authorization configuration
      * @param LoggerInterface|null $logger Logger instance
      */
     public function __construct(
         AuthorizationConfig $config,
         ?LoggerInterface $logger = null
     ) {
         $this->config = $config;
         $this->tokenStore = $config->getTokenStore();
         $this->logger = $logger ?? new NullLogger();
     }
 
     /**
      * Generate and store a new access token.
      *
      * @param string $clientId Client identifier
      * @param string|null $userId User identifier (null for client credentials)
      * @param string|null $scope Granted scope
      * @param string $grantType The grant type used
      * @param array $additionalData Additional metadata to store
      * @return array Token response data
      */
     public function createAccessToken(
         string $clientId,
         ?string $userId = null,
         ?string $scope = null,
         string $grantType = 'authorization_code',
         array $additionalData = []
     ): array {
         $token = TokenGenerator::generateAccessToken();
         $expiresAt = TokenGenerator::generateExpiration($this->config->getTokenLifetime());
 
         $metadata = array_merge($additionalData, [
             'client_id' => $clientId,
             'user_id' => $userId,
             'scope' => $scope,
             'grant_type' => $grantType,
             'expires_at' => $expiresAt,
             'issued_at' => time()
         ]);
 
         $this->tokenStore->storeAccessToken($token, $metadata);
 
         $this->logger->info('Access token created', [
             'client_id' => $clientId,
             'user_id' => $userId,
             'grant_type' => $grantType
         ]);
 
         return [
             'access_token' => $token,
             'token_type' => 'Bearer',
             'expires_in' => $this->config->getTokenLifetime(),
             'scope' => $scope
         ];
     }
 
     /**
      * Generate and store a new refresh token.
      *
      * @param string $clientId Client identifier
      * @param string|null $userId User identifier
      * @param string|null $scope Granted scope
      * @param string $accessToken Associated access token
      * @return string Refresh token
      */
     public function createRefreshToken(
         string $clientId,
         ?string $userId,
         ?string $scope,
         string $accessToken
     ): string {
         $token = TokenGenerator::generateRefreshToken();
         $expiresAt = TokenGenerator::generateExpiration($this->config->getRefreshTokenLifetime());
 
         $metadata = [
             'client_id' => $clientId,
             'user_id' => $userId,
             'scope' => $scope,
             'expires_at' => $expiresAt,
             'issued_at' => time(),
             'access_token' => $accessToken
         ];
 
         $this->tokenStore->storeRefreshToken($token, $metadata);
 
         $this->logger->info('Refresh token created', [
             'client_id' => $clientId,
             'user_id' => $userId
         ]);
 
         return $token;
     }
 
     /**
      * Generate and store a new authorization code.
      *
      * @param string $clientId Client identifier
      * @param string|null $userId User identifier
      * @param string $redirectUri Redirect URI
      * @param string|null $scope Requested scope
      * @param string|null $codeChallenge PKCE code challenge
      * @param string $codeChallengeMethod PKCE method
      * @param array $additionalData Additional metadata
      * @return string Authorization code
      */
     public function createAuthorizationCode(
         string $clientId,
         ?string $userId,
         string $redirectUri,
         ?string $scope,
         ?string $codeChallenge = null,
         string $codeChallengeMethod = 'S256',
         array $additionalData = []
     ): string {
         $code = TokenGenerator::generateAuthorizationCode();
         $expiresAt = TokenGenerator::generateExpiration($this->config->getAuthCodeLifetime());
 
         $metadata = array_merge($additionalData, [
             'client_id' => $clientId,
             'user_id' => $userId,
             'redirect_uri' => $redirectUri,
             'scope' => $scope,
             'expires_at' => $expiresAt,
             'issued_at' => time(),
             'code_challenge' => $codeChallenge,
             'code_challenge_method' => $codeChallengeMethod
         ]);
 
         $this->tokenStore->storeAuthorizationCode($code, $metadata);
 
         $this->logger->info('Authorization code created', [
             'client_id' => $clientId,
             'user_id' => $userId,
             'has_pkce' => $codeChallenge !== null
         ]);
 
         return $code;
     }
 
     /**
      * Validate an access token.
      *
      * @param string $token Access token
      * @return array|null Token metadata if valid, null otherwise
      */
     public function validateAccessToken(string $token): ?array
     {
         $metadata = $this->tokenStore->getAccessToken($token);
 
         if ($metadata === null) {
             $this->logger->debug('Access token not found');
             return null;
         }
 
         // Check expiration
         if (isset($metadata['expires_at']) && TokenGenerator::isExpired($metadata['expires_at'])) {
             $this->logger->debug('Access token expired', ['expires_at' => $metadata['expires_at']]);
             $this->tokenStore->deleteAccessToken($token);
             return null;
         }
 
         return $metadata;
     }
 
     /**
      * Validate a refresh token.
      *
      * @param string $token Refresh token
      * @return array|null Token metadata if valid, null otherwise
      */
     public function validateRefreshToken(string $token): ?array
     {
         $metadata = $this->tokenStore->getRefreshToken($token);
 
         if ($metadata === null) {
             $this->logger->debug('Refresh token not found');
             return null;
         }
 
         // Check expiration
         if (isset($metadata['expires_at']) && TokenGenerator::isExpired($metadata['expires_at'])) {
             $this->logger->debug('Refresh token expired');
             $this->tokenStore->deleteRefreshToken($token);
             return null;
         }
 
         return $metadata;
     }
 
     /**
      * Validate and consume an authorization code.
      *
      * @param string $code Authorization code
      * @param string $clientId Client identifier
      * @param string $redirectUri Redirect URI
      * @param string|null $codeVerifier PKCE code verifier
      * @return array|null Code metadata if valid, null otherwise
      */
     public function validateAuthorizationCode(
         string $code,
         string $clientId,
         string $redirectUri,
         ?string $codeVerifier = null
     ): ?array {
         $metadata = $this->tokenStore->getAuthorizationCode($code);
 
         if ($metadata === null) {
             $this->logger->debug('Authorization code not found');
             return null;
         }
 
         // Check expiration
         if (isset($metadata['expires_at']) && TokenGenerator::isExpired($metadata['expires_at'])) {
             $this->logger->debug('Authorization code expired');
             $this->tokenStore->deleteAuthorizationCode($code);
             return null;
         }
 
         // Validate client ID
         if ($metadata['client_id'] !== $clientId) {
             $this->logger->warning('Authorization code client mismatch', [
                 'expected' => $metadata['client_id'],
                 'provided' => $clientId
             ]);
             return null;
         }
 
         // Validate redirect URI
         if ($metadata['redirect_uri'] !== $redirectUri) {
             $this->logger->warning('Authorization code redirect URI mismatch');
             return null;
         }
 
         // Validate PKCE if present
         if (isset($metadata['code_challenge'])) {
             if ($codeVerifier === null) {
                 $this->logger->warning('PKCE code verifier required but not provided');
                 return null;
             }
 
             $method = $metadata['code_challenge_method'] ?? 'S256';
             if (!TokenGenerator::verifyCodeChallenge($codeVerifier, $metadata['code_challenge'], $method)) {
                 $this->logger->warning('PKCE verification failed');
                 return null;
             }
         } elseif ($this->config->isPkceRequired()) {
             $this->logger->warning('PKCE required but no code challenge present');
             return null;
         }
 
         // Authorization codes are single-use - delete immediately
         $this->tokenStore->deleteAuthorizationCode($code);
 
         $this->logger->info('Authorization code validated and consumed', [
             'client_id' => $clientId
         ]);
 
         return $metadata;
     }
 
     /**
      * Refresh an access token using a refresh token.
      *
      * @param string $refreshToken Refresh token
      * @param string $clientId Client identifier
      * @param string|null $scope Requested scope (must be subset of original)
      * @return array|null Token response data if successful
      */
     public function refreshAccessToken(
         string $refreshToken,
         string $clientId,
         ?string $scope = null
     ): ?array {
         $metadata = $this->validateRefreshToken($refreshToken);
 
         if ($metadata === null) {
             return null;
         }
 
         // Validate client ID
         if ($metadata['client_id'] !== $clientId) {
             $this->logger->warning('Refresh token client mismatch');
             return null;
         }
 
         // Validate scope (must be equal or narrower)
         $originalScope = $metadata['scope'] ?? '';
         if ($scope !== null && !$this->isScopeSubset($scope, $originalScope)) {
             $this->logger->warning('Invalid scope for refresh', [
                 'requested' => $scope,
                 'original' => $originalScope
             ]);
             return null;
         }
 
         // Use original scope if none specified
         $scope = $scope ?? $originalScope;
 
         // Revoke old access token if it exists
         if (isset($metadata['access_token'])) {
             $this->tokenStore->deleteAccessToken($metadata['access_token']);
         }
 
         // Create new access token
         $tokenData = $this->createAccessToken(
             $clientId,
             $metadata['user_id'] ?? null,
             $scope,
             'refresh_token'
         );
 
         // Update refresh token metadata with new access token
         $metadata['access_token'] = $tokenData['access_token'];
         $this->tokenStore->storeRefreshToken($refreshToken, $metadata);
 
         // Include refresh token in response
         $tokenData['refresh_token'] = $refreshToken;
 
         $this->logger->info('Access token refreshed', [
             'client_id' => $clientId
         ]);
 
         return $tokenData;
     }
 
     /**
      * Revoke a token.
      *
      * @param string $token Token to revoke
      * @param string $tokenType Token type hint (access_token or refresh_token)
      * @return bool True if token was revoked
      */
     public function revokeToken(string $token, string $tokenType = 'access_token'): bool
     {
         $revoked = false;
 
         if ($tokenType === 'refresh_token') {
             $metadata = $this->tokenStore->getRefreshToken($token);
             if ($metadata !== null) {
                 // Also revoke associated access token
                 if (isset($metadata['access_token'])) {
                     $this->tokenStore->deleteAccessToken($metadata['access_token']);
                 }
                 $this->tokenStore->deleteRefreshToken($token);
                 $revoked = true;
             }
         } else {
             // Try as access token first
             $metadata = $this->tokenStore->getAccessToken($token);
             if ($metadata !== null) {
                 $this->tokenStore->deleteAccessToken($token);
                 $revoked = true;
             }
         }
 
         if ($revoked) {
             $this->logger->info('Token revoked', ['type' => $tokenType]);
         }
 
         return $revoked;
     }
 
     /**
      * Clean up expired tokens.
      *
      * @return int Number of tokens cleaned up
      */
     public function cleanupExpiredTokens(): int
     {
         $count = $this->tokenStore->cleanupExpired();
         
         if ($count > 0) {
             $this->logger->info('Cleaned up expired tokens', ['count' => $count]);
         }
 
         return $count;
     }
 
     /**
      * Check if a scope is a subset of another scope.
      *
      * @param string $requested Requested scope
      * @param string $granted Granted scope
      * @return bool True if requested is subset of granted
      */
     private function isScopeSubset(string $requested, string $granted): bool
     {
         $requestedScopes = explode(' ', $requested);
         $grantedScopes = explode(' ', $granted);
 
         foreach ($requestedScopes as $scope) {
             if (!in_array($scope, $grantedScopes, true)) {
                 return false;
             }
         }
 
         return true;
     }
 
     /**
      * Get token store statistics.
      *
      * @return array Statistics
      */
     public function getStats(): array
     {
         if ($this->tokenStore instanceof Store\InMemoryTokenStore) {
             return $this->tokenStore->getStats();
         }
 
         return [];
     }
 }