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
 * Filename: Server/Auth/TokenStoreInterface.php
 */

declare(strict_types=1);

namespace Mcp\Server\Auth;

 /**
  * Interface for OAuth token storage implementations.
  * 
  * This interface defines the contract for storing and retrieving
  * OAuth access tokens, refresh tokens, and their associated metadata.
  */
 interface TokenStoreInterface
 {
     /**
      * Store an access token with its metadata.
      *
      * @param string $token The access token
      * @param array $metadata Token metadata including:
      *   - client_id: The OAuth client ID
      *   - user_id: Optional user identifier
      *   - scope: Granted scopes
      *   - expires_at: Unix timestamp of expiration
      *   - session_id: Optional MCP session ID
      *   - grant_type: The grant type used
      * @return void
      */
     public function storeAccessToken(string $token, array $metadata): void;
 
     /**
      * Retrieve access token metadata.
      *
      * @param string $token The access token
      * @return array|null Token metadata or null if not found
      */
     public function getAccessToken(string $token): ?array;
 
     /**
      * Delete an access token.
      *
      * @param string $token The access token to delete
      * @return void
      */
     public function deleteAccessToken(string $token): void;
 
     /**
      * Store a refresh token with its metadata.
      *
      * @param string $token The refresh token
      * @param array $metadata Token metadata including:
      *   - client_id: The OAuth client ID
      *   - user_id: Optional user identifier
      *   - scope: Granted scopes
      *   - expires_at: Unix timestamp of expiration
      *   - access_token: Associated access token
      * @return void
      */
     public function storeRefreshToken(string $token, array $metadata): void;
 
     /**
      * Retrieve refresh token metadata.
      *
      * @param string $token The refresh token
      * @return array|null Token metadata or null if not found
      */
     public function getRefreshToken(string $token): ?array;
 
     /**
      * Delete a refresh token.
      *
      * @param string $token The refresh token to delete
      * @return void
      */
     public function deleteRefreshToken(string $token): void;
 
     /**
      * Store an authorization code with its metadata.
      *
      * @param string $code The authorization code
      * @param array $metadata Code metadata including:
      *   - client_id: The OAuth client ID
      *   - user_id: Optional user identifier
      *   - redirect_uri: The redirect URI
      *   - scope: Requested scopes
      *   - expires_at: Unix timestamp of expiration
      *   - code_challenge: PKCE code challenge
      *   - code_challenge_method: PKCE method (S256)
      * @return void
      */
     public function storeAuthorizationCode(string $code, array $metadata): void;
 
     /**
      * Retrieve authorization code metadata.
      *
      * @param string $code The authorization code
      * @return array|null Code metadata or null if not found
      */
     public function getAuthorizationCode(string $code): ?array;
 
     /**
      * Delete an authorization code.
      *
      * @param string $code The authorization code to delete
      * @return void
      */
     public function deleteAuthorizationCode(string $code): void;
 
     /**
      * Clean up expired tokens.
      *
      * @return int Number of tokens cleaned up
      */
     public function cleanupExpired(): int;
 
     /**
      * Get all tokens for a specific client.
      *
      * @param string $clientId The client ID
      * @return array Array of token metadata
      */
     public function getTokensByClient(string $clientId): array;
 
     /**
      * Revoke all tokens for a specific client.
      *
      * @param string $clientId The client ID
      * @return int Number of tokens revoked
      */
     public function revokeClientTokens(string $clientId): int;
 }