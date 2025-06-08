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
 * Filename: Server/Auth/AuthorizationConfig.php
 */

 declare(strict_types=1);

 namespace Mcp\Server\Auth;
 
 /**
  * Configuration for OAuth authorization in MCP servers.
  * 
  * This class holds all configuration options for OAuth 2.1 authorization
  * including grant types, token lifetimes, and security settings.
  */
 class AuthorizationConfig
 {
     /**
      * Whether authorization is enabled.
      *
      * @var bool
      */
     private bool $enabled;
 
     /**
      * Whether authorization is required for all endpoints.
      *
      * @var bool
      */
     private bool $requireAuth;
 
     /**
      * OAuth issuer identifier (typically the server's base URL).
      *
      * @var string
      */
     private string $issuer;
 
     /**
      * Supported grant types.
      *
      * @var array<string>
      */
     private array $grantTypes;
 
     /**
      * Access token lifetime in seconds.
      *
      * @var int
      */
     private int $tokenLifetime;
 
     /**
      * Refresh token lifetime in seconds.
      *
      * @var int
      */
     private int $refreshTokenLifetime;
 
     /**
      * Authorization code lifetime in seconds.
      *
      * @var int
      */
     private int $authCodeLifetime;
 
     /**
      * Whether PKCE is required for authorization code grant.
      *
      * @var bool
      */
     private bool $pkceRequired;
 
     /**
      * Whether dynamic client registration is enabled.
      *
      * @var bool
      */
     private bool $dynamicRegistration;
 
     /**
      * Token store instance.
      *
      * @var TokenStoreInterface
      */
     private TokenStoreInterface $tokenStore;
 
     /**
      * Client store instance.
      *
      * @var ClientStoreInterface
      */
     private ClientStoreInterface $clientStore;
 
     /**
      * Public endpoints that don't require authorization.
      *
      * @var array<string>
      */
     private array $publicEndpoints;
 
     /**
      * Whether to enforce HTTPS for authorization endpoints.
      *
      * @var bool
      */
     private bool $requireHttps;
 
     /**
      * Supported response types.
      *
      * @var array<string>
      */
     private array $responseTypes;
 
     /**
      * Token endpoint authentication methods.
      *
      * @var array<string>
      */
     private array $tokenEndpointAuthMethods;
 
     /**
      * Constructor.
      *
      * @param array $config Configuration options
      */
     public function __construct(array $config = [])
     {
         // Set defaults
         $this->enabled = $config['enabled'] ?? false;
         $this->requireAuth = $config['require_auth'] ?? true;
         $this->issuer = $config['issuer'] ?? '';
         $this->grantTypes = $config['grant_types'] ?? ['authorization_code', 'client_credentials'];
         $this->tokenLifetime = $config['token_lifetime'] ?? 3600; // 1 hour
         $this->refreshTokenLifetime = $config['refresh_token_lifetime'] ?? 2592000; // 30 days
         $this->authCodeLifetime = $config['auth_code_lifetime'] ?? 600; // 10 minutes
         $this->pkceRequired = $config['pkce_required'] ?? true;
         $this->dynamicRegistration = $config['dynamic_registration'] ?? true;
         $this->publicEndpoints = $config['public_endpoints'] ?? [];
         $this->requireHttps = $config['require_https'] ?? true;
         $this->responseTypes = $config['response_types'] ?? ['code'];
         $this->tokenEndpointAuthMethods = $config['token_endpoint_auth_methods'] ?? 
             ['client_secret_basic', 'client_secret_post', 'none'];
 
         // Initialize stores if not provided
         if (isset($config['token_store']) && $config['token_store'] instanceof TokenStoreInterface) {
             $this->tokenStore = $config['token_store'];
         } else {
             $this->tokenStore = new Store\InMemoryTokenStore();
         }
 
         if (isset($config['client_store']) && $config['client_store'] instanceof ClientStoreInterface) {
             $this->clientStore = $config['client_store'];
         } else {
             $this->clientStore = new Store\InMemoryClientStore();
         }
 
         // Add OAuth endpoints to public endpoints
         $this->addOAuthPublicEndpoints();
     }
 
     /**
      * Add OAuth-specific endpoints to the public endpoints list.
      *
      * @return void
      */
     private function addOAuthPublicEndpoints(): void
     {
         $oauthEndpoints = [
             '/.well-known/oauth-authorization-server',
             '/authorize',
             '/token',
             '/register',
             '/revoke',
             '/introspect'
         ];
 
         $this->publicEndpoints = array_unique(array_merge($this->publicEndpoints, $oauthEndpoints));
     }
 
     /**
      * Check if authorization is enabled.
      *
      * @return bool
      */
     public function isEnabled(): bool
     {
         return $this->enabled;
     }
 
     /**
      * Check if authorization is required for all endpoints.
      *
      * @return bool
      */
     public function isAuthRequired(): bool
     {
         return $this->requireAuth;
     }
 
     /**
      * Get the issuer identifier.
      *
      * @return string
      */
     public function getIssuer(): string
     {
         return $this->issuer;
     }
 
     /**
      * Set the issuer identifier.
      *
      * @param string $issuer
      * @return void
      */
     public function setIssuer(string $issuer): void
     {
         $this->issuer = $issuer;
     }
 
     /**
      * Get supported grant types.
      *
      * @return array<string>
      */
     public function getGrantTypes(): array
     {
         return $this->grantTypes;
     }
 
     /**
      * Check if a grant type is supported.
      *
      * @param string $grantType
      * @return bool
      */
     public function isGrantTypeSupported(string $grantType): bool
     {
         return in_array($grantType, $this->grantTypes, true);
     }
 
     /**
      * Get access token lifetime.
      *
      * @return int
      */
     public function getTokenLifetime(): int
     {
         return $this->tokenLifetime;
     }
 
     /**
      * Get refresh token lifetime.
      *
      * @return int
      */
     public function getRefreshTokenLifetime(): int
     {
         return $this->refreshTokenLifetime;
     }
 
     /**
      * Get authorization code lifetime.
      *
      * @return int
      */
     public function getAuthCodeLifetime(): int
     {
         return $this->authCodeLifetime;
     }
 
     /**
      * Check if PKCE is required.
      *
      * @return bool
      */
     public function isPkceRequired(): bool
     {
         return $this->pkceRequired;
     }
 
     /**
      * Check if dynamic registration is enabled.
      *
      * @return bool
      */
     public function isDynamicRegistrationEnabled(): bool
     {
         return $this->dynamicRegistration;
     }
 
     /**
      * Get the token store.
      *
      * @return TokenStoreInterface
      */
     public function getTokenStore(): TokenStoreInterface
     {
         return $this->tokenStore;
     }
 
     /**
      * Get the client store.
      *
      * @return ClientStoreInterface
      */
     public function getClientStore(): ClientStoreInterface
     {
         return $this->clientStore;
     }
 
     /**
      * Check if an endpoint requires authorization.
      *
      * @param string $endpoint
      * @return bool
      */
     public function isEndpointProtected(string $endpoint): bool
     {
         if (!$this->enabled || !$this->requireAuth) {
             return false;
         }
 
         // Normalize endpoint
         $endpoint = '/' . ltrim($endpoint, '/');
 
         // Check if it's in the public endpoints list
         foreach ($this->publicEndpoints as $publicEndpoint) {
             if ($endpoint === $publicEndpoint || str_starts_with($endpoint, $publicEndpoint)) {
                 return false;
             }
         }
 
         return true;
     }
 
     /**
      * Add a public endpoint.
      *
      * @param string $endpoint
      * @return void
      */
     public function addPublicEndpoint(string $endpoint): void
     {
         $endpoint = '/' . ltrim($endpoint, '/');
         if (!in_array($endpoint, $this->publicEndpoints, true)) {
             $this->publicEndpoints[] = $endpoint;
         }
     }
 
     /**
      * Check if HTTPS is required.
      *
      * @return bool
      */
     public function isHttpsRequired(): bool
     {
         return $this->requireHttps;
     }
 
     /**
      * Get supported response types.
      *
      * @return array<string>
      */
     public function getResponseTypes(): array
     {
         return $this->responseTypes;
     }
 
     /**
      * Get token endpoint authentication methods.
      *
      * @return array<string>
      */
     public function getTokenEndpointAuthMethods(): array
     {
         return $this->tokenEndpointAuthMethods;
     }
 
     /**
      * Validate the configuration.
      *
      * @return array<string> Array of validation errors
      */
     public function validate(): array
     {
         $errors = [];
 
         if ($this->enabled) {
             if (empty($this->issuer)) {
                 $errors[] = 'Issuer must be set when authorization is enabled';
             }
 
             if (empty($this->grantTypes)) {
                 $errors[] = 'At least one grant type must be supported';
             }
 
             if ($this->tokenLifetime <= 0) {
                 $errors[] = 'Token lifetime must be positive';
             }
 
             if ($this->refreshTokenLifetime <= 0) {
                 $errors[] = 'Refresh token lifetime must be positive';
             }
 
             if ($this->authCodeLifetime <= 0) {
                 $errors[] = 'Authorization code lifetime must be positive';
             }
 
             // Validate issuer is a valid URL
             if (!empty($this->issuer) && !filter_var($this->issuer, FILTER_VALIDATE_URL)) {
                 $errors[] = 'Issuer must be a valid URL';
             }
         }
 
         return $errors;
     }
 }