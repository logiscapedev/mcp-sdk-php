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
 * Filename: Server/Auth/ClientRegistrar.php
 */

 declare(strict_types=1);

 namespace Mcp\Server\Auth;
 
 use Mcp\Server\Auth\Utils\TokenGenerator;
 use Mcp\Server\Transport\Http\HttpMessage;
 use Psr\Log\LoggerInterface;
 use Psr\Log\NullLogger;
 
 /**
  * Handles OAuth 2.0 Dynamic Client Registration (RFC7591).
  * 
  * This class processes client registration requests, validates client
  * metadata, and manages client credentials.
  */
 class ClientRegistrar
 {
     /**
      * Authorization configuration.
      *
      * @var AuthorizationConfig
      */
     private AuthorizationConfig $config;
 
     /**
      * Client store.
      *
      * @var ClientStoreInterface
      */
     private ClientStoreInterface $clientStore;
 
     /**
      * Logger instance.
      *
      * @var LoggerInterface
      */
     private LoggerInterface $logger;
 
     /**
      * Required metadata fields for registration.
      *
      * @var array<string>
      */
     private const REQUIRED_FIELDS = [
         'redirect_uris'
     ];
 
     /**
      * Allowed client metadata fields.
      *
      * @var array<string>
      */
     private const ALLOWED_FIELDS = [
         'redirect_uris',
         'token_endpoint_auth_method',
         'grant_types',
         'response_types',
         'client_name',
         'client_uri',
         'logo_uri',
         'scope',
         'contacts',
         'tos_uri',
         'policy_uri',
         'software_id',
         'software_version'
     ];
 
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
         $this->clientStore = $config->getClientStore();
         $this->logger = $logger ?? new NullLogger();
     }
 
     /**
      * Handle client registration request.
      *
      * @param HttpMessage $request HTTP request
      * @return HttpMessage HTTP response
      */
     public function handleRegistrationRequest(HttpMessage $request): HttpMessage
     {
         // Check if dynamic registration is enabled
         if (!$this->config->isDynamicRegistrationEnabled()) {
             return $this->createErrorResponse(
                 'access_denied',
                 'Dynamic client registration is disabled',
                 403
             );
         }
 
         // Only POST method is allowed
         if ($request->getMethod() !== 'POST') {
             return $this->createErrorResponse(
                 'invalid_request',
                 'POST method required',
                 405
             );
         }
 
         // Validate content type
         $contentType = $request->getHeader('Content-Type');
         if ($contentType === null || stripos($contentType, 'application/json') === false) {
             return $this->createErrorResponse(
                 'invalid_request',
                 'Content-Type must be application/json',
                 400
             );
         }
 
         // Parse request body
         $body = $request->getBody();
         if ($body === null || $body === '') {
             return $this->createErrorResponse(
                 'invalid_request',
                 'Empty request body',
                 400
             );
         }
 
         try {
             $metadata = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
         } catch (\JsonException $e) {
             return $this->createErrorResponse(
                 'invalid_request',
                 'Invalid JSON: ' . $e->getMessage(),
                 400
             );
         }
 
         // Validate and process registration
         return $this->processRegistration($metadata);
     }
 
     /**
      * Process client registration.
      *
      * @param array $metadata Client metadata
      * @return HttpMessage HTTP response
      */
     private function processRegistration(array $metadata): HttpMessage
     {
         // Validate required fields
         foreach (self::REQUIRED_FIELDS as $field) {
             if (!isset($metadata[$field])) {
                 return $this->createErrorResponse(
                     'invalid_client_metadata',
                     "Missing required field: {$field}",
                     400
                 );
             }
         }
 
         // Validate redirect URIs
         $redirectUris = $metadata['redirect_uris'];
         if (!is_array($redirectUris) || empty($redirectUris)) {
             return $this->createErrorResponse(
                 'invalid_redirect_uri',
                 'redirect_uris must be a non-empty array',
                 400
             );
         }
 
         // Validate each redirect URI
         foreach ($redirectUris as $uri) {
             if (!$this->isValidRedirectUri($uri)) {
                 return $this->createErrorResponse(
                     'invalid_redirect_uri',
                     "Invalid redirect URI: {$uri}",
                     400
                 );
             }
         }
 
         // Set defaults
         $metadata = $this->applyDefaults($metadata);
 
         // Validate metadata values
         $validationError = $this->validateMetadata($metadata);
         if ($validationError !== null) {
             return $this->createErrorResponse(
                 'invalid_client_metadata',
                 $validationError,
                 400
             );
         }
 
         // Generate client credentials
         $clientId = TokenGenerator::generateClientId();
         $clientType = $this->determineClientType($metadata);
         
         // Generate client secret for confidential clients
         $clientSecret = null;
         if ($clientType === 'confidential') {
             $clientSecret = TokenGenerator::generateClientSecret();
         }
 
         // Generate registration access token
         $registrationToken = TokenGenerator::generateRegistrationToken();
 
         // Prepare client data for storage
         $clientData = [
             'client_secret' => $clientSecret,
             'client_type' => $clientType,
             'registration_access_token' => $registrationToken,
             'created_at' => time()
         ];
 
         // Add allowed metadata fields
         foreach (self::ALLOWED_FIELDS as $field) {
             if (isset($metadata[$field])) {
                 $clientData[$field] = $metadata[$field];
             }
         }
 
         // Store client
         $this->clientStore->storeClient($clientId, $clientData);
 
         $this->logger->info('Client registered', [
             'client_id' => $clientId,
             'client_name' => $metadata['client_name'] ?? 'Unknown',
             'client_type' => $clientType
         ]);
 
         // Build response
         $response = [
             'client_id' => $clientId,
             'client_id_issued_at' => time(),
             'registration_access_token' => $registrationToken,
             'registration_client_uri' => $this->config->getIssuer() . '/register/' . $clientId
         ];
 
         // Include client secret for confidential clients
         if ($clientSecret !== null) {
             $response['client_secret'] = $clientSecret;
             $response['client_secret_expires_at'] = 0; // Never expires
         }
 
         // Include all registered metadata
         foreach (self::ALLOWED_FIELDS as $field) {
             if (isset($clientData[$field])) {
                 $response[$field] = $clientData[$field];
             }
         }
 
         return HttpMessage::createJsonResponse($response, 201);
     }
 
     /**
      * Apply default values to client metadata.
      *
      * @param array $metadata Client metadata
      * @return array Metadata with defaults applied
      */
     private function applyDefaults(array $metadata): array
     {
         // Default grant types
         if (!isset($metadata['grant_types'])) {
             $metadata['grant_types'] = ['authorization_code'];
         }
 
         // Default response types
         if (!isset($metadata['response_types'])) {
             $metadata['response_types'] = ['code'];
         }
 
         // Default token endpoint auth method
         if (!isset($metadata['token_endpoint_auth_method'])) {
             // Determine based on redirect URIs
             $hasLocalhostOnly = true;
             foreach ($metadata['redirect_uris'] as $uri) {
                 if (!$this->isLocalhostUri($uri)) {
                     $hasLocalhostOnly = false;
                     break;
                 }
             }
 
             // Public clients (localhost only) use 'none', others use 'client_secret_basic'
             $metadata['token_endpoint_auth_method'] = $hasLocalhostOnly ? 'none' : 'client_secret_basic';
         }
 
         return $metadata;
     }
 
     /**
      * Validate client metadata.
      *
      * @param array $metadata Client metadata
      * @return string|null Error message or null if valid
      */
     private function validateMetadata(array $metadata): ?string
     {
         // Validate grant types
         if (isset($metadata['grant_types'])) {
             if (!is_array($metadata['grant_types'])) {
                 return 'grant_types must be an array';
             }
 
             foreach ($metadata['grant_types'] as $grantType) {
                 if (!$this->config->isGrantTypeSupported($grantType)) {
                     return "Unsupported grant type: {$grantType}";
                 }
             }
         }
 
         // Validate response types
         if (isset($metadata['response_types'])) {
             if (!is_array($metadata['response_types'])) {
                 return 'response_types must be an array';
             }
 
             $supportedResponseTypes = $this->config->getResponseTypes();
             foreach ($metadata['response_types'] as $responseType) {
                 if (!in_array($responseType, $supportedResponseTypes, true)) {
                     return "Unsupported response type: {$responseType}";
                 }
             }
         }
 
         // Validate token endpoint auth method
         if (isset($metadata['token_endpoint_auth_method'])) {
             $supportedMethods = $this->config->getTokenEndpointAuthMethods();
             if (!in_array($metadata['token_endpoint_auth_method'], $supportedMethods, true)) {
                 return "Unsupported token endpoint auth method: {$metadata['token_endpoint_auth_method']}";
             }
         }
 
         // Validate URIs
         $uriFields = ['client_uri', 'logo_uri', 'tos_uri', 'policy_uri'];
         foreach ($uriFields as $field) {
             if (isset($metadata[$field]) && !filter_var($metadata[$field], FILTER_VALIDATE_URL)) {
                 return "{$field} must be a valid URL";
             }
         }
 
         // Validate contacts
         if (isset($metadata['contacts'])) {
             if (!is_array($metadata['contacts'])) {
                 return 'contacts must be an array';
             }
 
             foreach ($metadata['contacts'] as $contact) {
                 if (!is_string($contact) || !filter_var($contact, FILTER_VALIDATE_EMAIL)) {
                     return 'contacts must contain valid email addresses';
                 }
             }
         }
 
         return null;
     }
 
     /**
      * Determine client type based on metadata.
      *
      * @param array $metadata Client metadata
      * @return string 'public' or 'confidential'
      */
     private function determineClientType(array $metadata): string
     {
         // If auth method is 'none', it's a public client
         if (($metadata['token_endpoint_auth_method'] ?? '') === 'none') {
             return 'public';
         }
 
         // If all redirect URIs are localhost, consider it public
         $allLocalhost = true;
         foreach ($metadata['redirect_uris'] as $uri) {
             if (!$this->isLocalhostUri($uri)) {
                 $allLocalhost = false;
                 break;
             }
         }
 
         return $allLocalhost ? 'public' : 'confidential';
     }
 
     /**
      * Validate a redirect URI.
      *
      * @param string $uri Redirect URI
      * @return bool True if valid
      */
     private function isValidRedirectUri(string $uri): bool
     {
         // Must be a valid URL
         if (!filter_var($uri, FILTER_VALIDATE_URL)) {
             return false;
         }
 
         $parsed = parse_url($uri);
         if ($parsed === false) {
             return false;
         }
 
         // Must have a scheme
         if (!isset($parsed['scheme'])) {
             return false;
         }
 
         // Localhost URIs can use HTTP
         if ($this->isLocalhostUri($uri)) {
             return in_array($parsed['scheme'], ['http', 'https'], true);
         }
 
         // Non-localhost must use HTTPS (per MCP spec section 2.7)
         return $parsed['scheme'] === 'https';
     }
 
     /**
      * Check if a URI is a localhost URI.
      *
      * @param string $uri URI to check
      * @return bool True if localhost
      */
     private function isLocalhostUri(string $uri): bool
     {
         $parsed = parse_url($uri);
         if ($parsed === false || !isset($parsed['host'])) {
             return false;
         }
 
         $host = strtolower($parsed['host']);
         return in_array($host, ['localhost', '127.0.0.1', '[::1]'], true);
     }
 
     /**
      * Create error response.
      *
      * @param string $error Error code
      * @param string $description Error description
      * @param int $statusCode HTTP status code
      * @return HttpMessage HTTP response
      */
     private function createErrorResponse(string $error, string $description, int $statusCode): HttpMessage
     {
         return HttpMessage::createJsonResponse([
             'error' => $error,
             'error_description' => $description
         ], $statusCode);
     }
 
     /**
      * Handle client configuration update request.
      *
      * @param HttpMessage $request HTTP request
      * @param string $clientId Client ID from URL
      * @return HttpMessage HTTP response
      */
     public function handleUpdateRequest(HttpMessage $request, string $clientId): HttpMessage
     {
         // Validate registration access token
         $authHeader = $request->getHeader('Authorization');
         if ($authHeader === null) {
             return $this->createErrorResponse(
                 'invalid_token',
                 'Missing registration access token',
                 401
             );
         }
 
         $token = TokenGenerator::extractBearerToken($authHeader);
         if ($token === null) {
             return $this->createErrorResponse(
                 'invalid_token',
                 'Invalid authorization header',
                 401
             );
         }
 
         // Find client by registration token
         $client = $this->clientStore->findByRegistrationToken($token);
         if ($client === null || $client['client_id'] !== $clientId) {
             return $this->createErrorResponse(
                 'invalid_token',
                 'Invalid registration access token',
                 401
             );
         }
 
         // For now, we'll just return the current configuration
         // Full update implementation would parse the request body and update allowed fields
         
         $response = ['client_id' => $clientId];
         foreach (self::ALLOWED_FIELDS as $field) {
             if (isset($client[$field])) {
                 $response[$field] = $client[$field];
             }
         }
 
         return HttpMessage::createJsonResponse($response, 200);
     }
 }