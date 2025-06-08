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
 * Filename: Server/Auth/ClientStoreInterface.php
 */

declare(strict_types=1);

namespace Mcp\Server\Auth;

/**
 * Interface for OAuth client storage implementations.
 * 
 * This interface defines the contract for storing and retrieving
 * OAuth client registrations and their credentials.
 */
interface ClientStoreInterface
{
    /**
     * Store a client registration.
     *
     * @param string $clientId The client identifier
     * @param array $metadata Client metadata including:
     *   - client_secret: Optional client secret (for confidential clients)
     *   - client_name: Human-readable client name
     *   - redirect_uris: Array of allowed redirect URIs
     *   - grant_types: Array of allowed grant types
     *   - response_types: Array of allowed response types
     *   - scope: Default scope for the client
     *   - token_endpoint_auth_method: How client authenticates at token endpoint
     *   - client_type: 'confidential' or 'public'
     *   - created_at: Unix timestamp of registration
     *   - registration_access_token: Optional token for updating registration
     * @return void
     */
    public function storeClient(string $clientId, array $metadata): void;

    /**
     * Retrieve client metadata.
     *
     * @param string $clientId The client identifier
     * @return array|null Client metadata or null if not found
     */
    public function getClient(string $clientId): ?array;

    /**
     * Update client metadata.
     *
     * @param string $clientId The client identifier
     * @param array $metadata Updated client metadata
     * @return bool True if updated, false if client not found
     */
    public function updateClient(string $clientId, array $metadata): bool;

    /**
     * Delete a client registration.
     *
     * @param string $clientId The client identifier to delete
     * @return bool True if deleted, false if not found
     */
    public function deleteClient(string $clientId): bool;

    /**
     * Validate client credentials.
     *
     * @param string $clientId The client identifier
     * @param string|null $clientSecret The client secret (null for public clients)
     * @return bool True if credentials are valid
     */
    public function validateCredentials(string $clientId, ?string $clientSecret): bool;

    /**
     * Check if a redirect URI is allowed for a client.
     *
     * @param string $clientId The client identifier
     * @param string $redirectUri The redirect URI to check
     * @return bool True if the redirect URI is allowed
     */
    public function isRedirectUriAllowed(string $clientId, string $redirectUri): bool;

    /**
     * Check if a grant type is allowed for a client.
     *
     * @param string $clientId The client identifier
     * @param string $grantType The grant type to check
     * @return bool True if the grant type is allowed
     */
    public function isGrantTypeAllowed(string $clientId, string $grantType): bool;

    /**
     * Get all registered clients.
     *
     * @param int $limit Maximum number of clients to return
     * @param int $offset Number of clients to skip
     * @return array Array of client metadata
     */
    public function getAllClients(int $limit = 100, int $offset = 0): array;

    /**
     * Count total registered clients.
     *
     * @return int Total number of clients
     */
    public function countClients(): int;

    /**
     * Find a client by its registration access token.
     *
     * @param string $token The registration access token
     * @return array|null Client metadata or null if not found
     */
    public function findByRegistrationToken(string $token): ?array;
}