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
 * Filename: Server/Auth/AuthorizationMiddleware.php
 */

 declare(strict_types=1);

 namespace Mcp\Server\Auth;
 
 use Mcp\Server\Auth\Utils\TokenGenerator;
 use Mcp\Server\Transport\Http\HttpMessage;
 use Psr\Log\LoggerInterface;
 use Psr\Log\NullLogger;
 
 /**
  * Middleware for handling OAuth authorization in MCP servers.
  * 
  * This class validates Bearer tokens from Authorization headers and
  * determines whether requests should be allowed based on the authorization
  * configuration and token validity.
  */
 class AuthorizationMiddleware
 {
     /**
      * Authorization configuration.
      *
      * @var AuthorizationConfig
      */
     private AuthorizationConfig $config;
 
     /**
      * Token manager.
      *
      * @var TokenManager
      */
     private TokenManager $tokenManager;
 
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
      * @param TokenManager $tokenManager Token manager
      * @param LoggerInterface|null $logger Logger instance
      */
     public function __construct(
         AuthorizationConfig $config,
         TokenManager $tokenManager,
         ?LoggerInterface $logger = null
     ) {
         $this->config = $config;
         $this->tokenManager = $tokenManager;
         $this->logger = $logger ?? new NullLogger();
     }
 
     /**
      * Check authorization for an HTTP request.
      *
      * @param HttpMessage $request HTTP request
      * @param string $endpoint The endpoint being accessed
      * @return array Authorization result with keys:
      *   - authorized: bool Whether the request is authorized
      *   - token_metadata: array|null Token metadata if authorized
      *   - error: string|null Error message if not authorized
      *   - error_code: string|null OAuth error code
      */
     public function checkAuthorization(HttpMessage $request, string $endpoint): array
     {
         // Check if authorization is enabled
         if (!$this->config->isEnabled()) {
             return [
                 'authorized' => true,
                 'token_metadata' => null,
                 'error' => null,
                 'error_code' => null
             ];
         }
 
         // Check if endpoint requires authorization
         if (!$this->config->isEndpointProtected($endpoint)) {
             $this->logger->debug('Endpoint is public, skipping authorization', ['endpoint' => $endpoint]);
             return [
                 'authorized' => true,
                 'token_metadata' => null,
                 'error' => null,
                 'error_code' => null
             ];
         }
 
         // Check HTTPS requirement for OAuth endpoints
         if ($this->config->isHttpsRequired() && $this->isOAuthEndpoint($endpoint)) {
             if (!$this->isHttpsRequest($request)) {
                 $this->logger->warning('HTTPS required for OAuth endpoint', ['endpoint' => $endpoint]);
                 return [
                     'authorized' => false,
                     'token_metadata' => null,
                     'error' => 'HTTPS required for OAuth endpoints',
                     'error_code' => 'invalid_request'
                 ];
             }
         }
 
         // Extract Bearer token
         $token = $this->extractBearerToken($request);
         if ($token === null) {
             $this->logger->debug('No Bearer token provided');
             return [
                 'authorized' => false,
                 'token_metadata' => null,
                 'error' => 'Bearer token required',
                 'error_code' => 'invalid_request'
             ];
         }
 
         // Validate token
         $tokenMetadata = $this->tokenManager->validateAccessToken($token);
         if ($tokenMetadata === null) {
             $this->logger->debug('Invalid or expired token');
             return [
                 'authorized' => false,
                 'token_metadata' => null,
                 'error' => 'Invalid or expired token',
                 'error_code' => 'invalid_token'
             ];
         }
 
         // Check token scope if endpoint requires specific scope
         $requiredScope = $this->getEndpointRequiredScope($endpoint);
         if ($requiredScope !== null && !$this->hasRequiredScope($tokenMetadata, $requiredScope)) {
             $this->logger->warning('Insufficient scope', [
                 'required' => $requiredScope,
                 'granted' => $tokenMetadata['scope'] ?? ''
             ]);
             return [
                 'authorized' => false,
                 'token_metadata' => $tokenMetadata,
                 'error' => 'Insufficient scope',
                 'error_code' => 'insufficient_scope'
             ];
         }
 
         $this->logger->debug('Request authorized', [
             'client_id' => $tokenMetadata['client_id'] ?? '',
             'user_id' => $tokenMetadata['user_id'] ?? '',
             'endpoint' => $endpoint
         ]);
 
         return [
             'authorized' => true,
             'token_metadata' => $tokenMetadata,
             'error' => null,
             'error_code' => null
         ];
     }
 
     /**
      * Extract Bearer token from request.
      *
      * @param HttpMessage $request HTTP request
      * @return string|null Token or null if not found
      */
     public function extractBearerToken(HttpMessage $request): ?string
     {
         $authHeader = $request->getHeader('Authorization');
         if ($authHeader === null) {
             return null;
         }
 
         return TokenGenerator::extractBearerToken($authHeader);
     }
 
     /**
      * Create an unauthorized response.
      *
      * @param string|null $error Error message
      * @param string|null $errorCode OAuth error code
      * @param string|null $scope Required scope
      * @return HttpMessage HTTP response
      */
     public function createUnauthorizedResponse(
         ?string $error = null,
         ?string $errorCode = null,
         ?string $scope = null
     ): HttpMessage {
         $response = HttpMessage::createJsonResponse([
             'error' => $errorCode ?? 'unauthorized',
             'error_description' => $error ?? 'Authorization required'
         ], 401);
 
         // Build WWW-Authenticate header
         $authenticateParams = ['Bearer'];
         
         if ($this->config->isEnabled()) {
             $authenticateParams[] = 'realm="' . $this->config->getIssuer() . '"';
         }
 
         if ($errorCode !== null) {
             $authenticateParams[] = 'error="' . $errorCode . '"';
         }
 
         if ($error !== null) {
             // Escape quotes in error description
             $escapedError = str_replace('"', '\"', $error);
             $authenticateParams[] = 'error_description="' . $escapedError . '"';
         }
 
         if ($scope !== null) {
             $authenticateParams[] = 'scope="' . $scope . '"';
         }
 
         $response->setHeader('WWW-Authenticate', implode(' ', $authenticateParams));
 
         return $response;
     }
 
     /**
      * Create a forbidden response.
      *
      * @param string|null $error Error message
      * @return HttpMessage HTTP response
      */
     public function createForbiddenResponse(?string $error = null): HttpMessage
     {
         return HttpMessage::createJsonResponse([
             'error' => 'forbidden',
             'error_description' => $error ?? 'Insufficient permissions'
         ], 403);
     }
 
     /**
      * Check if a request is using HTTPS.
      *
      * @param HttpMessage $request HTTP request
      * @return bool True if HTTPS
      */
     private function isHttpsRequest(HttpMessage $request): bool
     {
         // Check X-Forwarded-Proto header (for proxies)
         $forwardedProto = $request->getHeader('X-Forwarded-Proto');
         if ($forwardedProto === 'https') {
             return true;
         }
 
         // Check if URI starts with https://
         $uri = $request->getUri();
         if ($uri !== null && str_starts_with($uri, 'https://')) {
             return true;
         }
 
         // In CLI/testing environments, check for a flag
         if (getenv('MCP_ASSUME_HTTPS') === 'true') {
             return true;
         }
 
         return false;
     }
 
     /**
      * Check if an endpoint is an OAuth endpoint.
      *
      * @param string $endpoint Endpoint path
      * @return bool True if OAuth endpoint
      */
     private function isOAuthEndpoint(string $endpoint): bool
     {
         $oauthEndpoints = [
             '/.well-known/oauth-authorization-server',
             '/authorize',
             '/token',
             '/register',
             '/revoke',
             '/introspect'
         ];
 
         $normalizedEndpoint = '/' . ltrim($endpoint, '/');
         return in_array($normalizedEndpoint, $oauthEndpoints, true);
     }
 
     /**
      * Get required scope for an endpoint.
      *
      * @param string $endpoint Endpoint path
      * @return string|null Required scope or null if none
      */
     private function getEndpointRequiredScope(string $endpoint): ?string
     {
         // This is a placeholder for endpoint-specific scope requirements
         // In a real implementation, this might come from configuration
         // or be determined by the endpoint pattern
         
         // For now, MCP endpoints don't require specific scopes
         return null;
     }
 
     /**
      * Check if token has required scope.
      *
      * @param array $tokenMetadata Token metadata
      * @param string $requiredScope Required scope
      * @return bool True if token has required scope
      */
     private function hasRequiredScope(array $tokenMetadata, string $requiredScope): bool
     {
         $grantedScope = $tokenMetadata['scope'] ?? '';
         if (empty($grantedScope)) {
             return false;
         }
 
         $grantedScopes = explode(' ', $grantedScope);
         $requiredScopes = explode(' ', $requiredScope);
 
         foreach ($requiredScopes as $scope) {
             if (!in_array($scope, $grantedScopes, true)) {
                 return false;
             }
         }
 
         return true;
     }
 
     /**
      * Get client ID from token metadata.
      *
      * @param array|null $tokenMetadata Token metadata
      * @return string|null Client ID or null
      */
     public function getClientId(?array $tokenMetadata): ?string
     {
         return $tokenMetadata['client_id'] ?? null;
     }
 
     /**
      * Get user ID from token metadata.
      *
      * @param array|null $tokenMetadata Token metadata
      * @return string|null User ID or null
      */
     public function getUserId(?array $tokenMetadata): ?string
     {
         return $tokenMetadata['user_id'] ?? null;
     }
 
     /**
      * Get granted scope from token metadata.
      *
      * @param array|null $tokenMetadata Token metadata
      * @return string|null Scope or null
      */
     public function getScope(?array $tokenMetadata): ?string
     {
         return $tokenMetadata['scope'] ?? null;
     }
 }