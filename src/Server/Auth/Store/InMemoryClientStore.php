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
 * Filename: Server/Auth/Store/InMemoryClientStore.php
 */

 declare(strict_types=1);

 namespace Mcp\Server\Auth\Store;
 
 use Mcp\Server\Auth\ClientStoreInterface;
 
 /**
  * In-memory implementation of client storage.
  * 
  * This implementation stores OAuth clients in memory and is suitable for
  * development, testing, or single-instance deployments. Client registrations
  * are lost when the process terminates.
  */
 class InMemoryClientStore implements ClientStoreInterface
 {
     /**
      * Client registrations storage.
      *
      * @var array<string, array>
      */
     private array $clients = [];
 
     /**
      * @inheritDoc
      */
     public function storeClient(string $clientId, array $metadata): void
     {
         $this->clients[$clientId] = $metadata;
     }
 
     /**
      * @inheritDoc
      */
     public function getClient(string $clientId): ?array
     {
         return $this->clients[$clientId] ?? null;
     }
 
     /**
      * @inheritDoc
      */
     public function updateClient(string $clientId, array $metadata): bool
     {
         if (!isset($this->clients[$clientId])) {
             return false;
         }
 
         // Merge with existing metadata to preserve fields not being updated
         $this->clients[$clientId] = array_merge($this->clients[$clientId], $metadata);
         return true;
     }
 
     /**
      * @inheritDoc
      */
     public function deleteClient(string $clientId): bool
     {
         if (!isset($this->clients[$clientId])) {
             return false;
         }
 
         unset($this->clients[$clientId]);
         return true;
     }
 
     /**
      * @inheritDoc
      */
     public function validateCredentials(string $clientId, ?string $clientSecret): bool
     {
         $client = $this->getClient($clientId);
         if ($client === null) {
             return false;
         }
 
         // Check client type
         $clientType = $client['client_type'] ?? 'confidential';
 
         if ($clientType === 'public') {
             // Public clients don't have secrets
             return $clientSecret === null;
         }
 
         // Confidential clients must have a secret
         if (!isset($client['client_secret'])) {
             return false;
         }
 
         // Use timing-safe comparison
         return hash_equals($client['client_secret'], $clientSecret ?? '');
     }
 
     /**
      * @inheritDoc
      */
     public function isRedirectUriAllowed(string $clientId, string $redirectUri): bool
     {
         $client = $this->getClient($clientId);
         if ($client === null || !isset($client['redirect_uris'])) {
             return false;
         }
 
         $allowedUris = $client['redirect_uris'];
         if (!is_array($allowedUris)) {
             return false;
         }
 
         // Exact match required for security
         return in_array($redirectUri, $allowedUris, true);
     }
 
     /**
      * @inheritDoc
      */
     public function isGrantTypeAllowed(string $clientId, string $grantType): bool
     {
         $client = $this->getClient($clientId);
         if ($client === null) {
             return false;
         }
 
         // If no grant types specified, allow common defaults
         if (!isset($client['grant_types'])) {
             $defaultGrants = ['authorization_code'];
             return in_array($grantType, $defaultGrants, true);
         }
 
         $allowedGrants = $client['grant_types'];
         if (!is_array($allowedGrants)) {
             return false;
         }
 
         return in_array($grantType, $allowedGrants, true);
     }
 
     /**
      * @inheritDoc
      */
     public function getAllClients(int $limit = 100, int $offset = 0): array
     {
         // Get all client IDs and sort them for consistent ordering
         $clientIds = array_keys($this->clients);
         sort($clientIds);
 
         // Apply pagination
         $paginatedIds = array_slice($clientIds, $offset, $limit);
 
         // Build result array
         $result = [];
         foreach ($paginatedIds as $clientId) {
             $metadata = $this->clients[$clientId];
             // Include client_id in the result
             $result[] = array_merge(['client_id' => $clientId], $metadata);
         }
 
         return $result;
     }
 
     /**
      * @inheritDoc
      */
     public function countClients(): int
     {
         return count($this->clients);
     }
 
     /**
      * @inheritDoc
      */
     public function findByRegistrationToken(string $token): ?array
     {
         foreach ($this->clients as $clientId => $metadata) {
             if (isset($metadata['registration_access_token']) && 
                 hash_equals($metadata['registration_access_token'], $token)) {
                 // Include client_id in the result
                 return array_merge(['client_id' => $clientId], $metadata);
             }
         }
 
         return null;
     }
 
     /**
      * Check if a client exists.
      *
      * @param string $clientId The client identifier
      * @return bool True if the client exists
      */
     public function exists(string $clientId): bool
     {
         return isset($this->clients[$clientId]);
     }
 
     /**
      * Get storage statistics.
      *
      * @return array Storage statistics
      */
     public function getStats(): array
     {
         $publicClients = 0;
         $confidentialClients = 0;
 
         foreach ($this->clients as $client) {
             $type = $client['client_type'] ?? 'confidential';
             if ($type === 'public') {
                 $publicClients++;
             } else {
                 $confidentialClients++;
             }
         }
 
         return [
             'total_clients' => count($this->clients),
             'public_clients' => $publicClients,
             'confidential_clients' => $confidentialClients
         ];
     }
 }