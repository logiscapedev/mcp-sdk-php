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
 * Filename: Server/Auth/OAuthServer.php
 */

 declare(strict_types=1);

 namespace Mcp\Server\Auth;
 
 use Mcp\Server\Auth\Utils\TokenGenerator;
 use Mcp\Server\Transport\Http\HttpMessage;
 use Psr\Log\LoggerInterface;
 use Psr\Log\NullLogger;
 
 /**
  * OAuth 2.1 server implementation for MCP.
  * 
  * This class handles all OAuth endpoints including metadata discovery,
  * authorization, token issuance, and dynamic client registration.
  */
 class OAuthServer
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
         $this->tokenManager = new TokenManager($config, $logger);
         $this->clientStore = $config->getClientStore();
         $this->logger = $logger ?? new NullLogger();
     }
 
     /**
      * Handle OAuth metadata discovery request.
      *
      * @param HttpMessage $request HTTP request
      * @return HttpMessage HTTP response
      */
     public function handleMetadataRequest(HttpMessage $request): HttpMessage
     {
         $issuer = $this->config->getIssuer();
         
         // Build metadata document per RFC8414
         $metadata = [
             'issuer' => $issuer,
             'authorization_endpoint' => $issuer . '/authorize',
             'token_endpoint' => $issuer . '/token',
             'token_endpoint_auth_methods_supported' => $this->config->getTokenEndpointAuthMethods(),
             'grant_types_supported' => $this->config->getGrantTypes(),
             'response_types_supported' => $this->config->getResponseTypes(),
             'code_challenge_methods_supported' => ['S256', 'plain'],
             'service_documentation' => 'https://modelcontextprotocol.io/docs/concepts/authorization',
         ];
 
         // Add optional endpoints if supported
         if ($this->config->isDynamicRegistrationEnabled()) {
             $metadata['registration_endpoint'] = $issuer . '/register';
         }
 
         $metadata['revocation_endpoint'] = $issuer . '/revoke';
         $metadata['introspection_endpoint'] = $issuer . '/introspect';
 
         // Log the MCP protocol version if provided
         $mcpVersion = $request->getHeader('MCP-Protocol-Version');
         if ($mcpVersion !== null) {
             $this->logger->info('OAuth metadata requested', ['mcp_version' => $mcpVersion]);
         }
 
         return HttpMessage::createJsonResponse($metadata, 200)
             ->setHeader('Cache-Control', 'max-age=3600');
     }
 
     /**
      * Handle authorization request.
      *
      * @param HttpMessage $request HTTP request
      * @return HttpMessage HTTP response
      */
     public function handleAuthorizeRequest(HttpMessage $request): HttpMessage
     {
         $params = $request->getQueryParams();
 
         // Validate required parameters
         $clientId = $params['client_id'] ?? null;
         $redirectUri = $params['redirect_uri'] ?? null;
         $responseType = $params['response_type'] ?? null;
         $state = $params['state'] ?? null;
 
         if (!$clientId || !$redirectUri || !$responseType) {
             return $this->createErrorResponse('invalid_request', 'Missing required parameters', 400);
         }
 
         // Only support authorization code flow
         if ($responseType !== 'code') {
             return $this->createAuthorizationErrorResponse(
                 $redirectUri,
                 'unsupported_response_type',
                 'Only authorization code flow is supported',
                 $state
             );
         }
 
         // Validate client
         $client = $this->clientStore->getClient($clientId);
         if ($client === null) {
             return $this->createErrorResponse('invalid_client', 'Unknown client', 401);
         }
 
         // Validate redirect URI
         if (!$this->clientStore->isRedirectUriAllowed($clientId, $redirectUri)) {
             return $this->createErrorResponse('invalid_request', 'Invalid redirect URI', 400);
         }
 
         // Check grant type allowed
         if (!$this->clientStore->isGrantTypeAllowed($clientId, 'authorization_code')) {
             return $this->createAuthorizationErrorResponse(
                 $redirectUri,
                 'unauthorized_client',
                 'Client not authorized for authorization code grant',
                 $state
             );
         }
 
         // Extract PKCE parameters
         $codeChallenge = $params['code_challenge'] ?? null;
         $codeChallengeMethod = $params['code_challenge_method'] ?? 'plain';
 
         // Validate PKCE if required
         if ($this->config->isPkceRequired() && !$codeChallenge) {
             return $this->createAuthorizationErrorResponse(
                 $redirectUri,
                 'invalid_request',
                 'PKCE code challenge required',
                 $state
             );
         }
 
         // Validate code challenge method
         if ($codeChallenge && !in_array($codeChallengeMethod, ['plain', 'S256'], true)) {
             return $this->createAuthorizationErrorResponse(
                 $redirectUri,
                 'invalid_request',
                 'Invalid code challenge method',
                 $state
             );
         }
 
         // In a real implementation, this would show a consent screen
         // For MCP, we'll auto-approve for now (servers should implement their own consent)
         $userId = $this->authenticateUser($request);
         if ($userId === null) {
             // Return HTML page for user authentication
             return $this->createAuthenticationPage($request);
         }
 
         // Generate authorization code
         $scope = $params['scope'] ?? null;
         $code = $this->tokenManager->createAuthorizationCode(
             $clientId,
             $userId,
             $redirectUri,
             $scope,
             $codeChallenge,
             $codeChallengeMethod
         );
 
         // Build redirect URL
         $redirectParams = ['code' => $code];
         if ($state !== null) {
             $redirectParams['state'] = $state;
         }
 
         $redirectUrl = $redirectUri . '?' . http_build_query($redirectParams);
 
         $this->logger->info('Authorization code issued', [
             'client_id' => $clientId,
             'user_id' => $userId
         ]);
 
         return HttpMessage::createEmptyResponse(302)
             ->setHeader('Location', $redirectUrl);
     }
 
     /**
      * Handle token request.
      *
      * @param HttpMessage $request HTTP request
      * @return HttpMessage HTTP response
      */
     public function handleTokenRequest(HttpMessage $request): HttpMessage
     {
         if ($request->getMethod() !== 'POST') {
             return $this->createErrorResponse('invalid_request', 'POST method required', 405);
         }
 
         // Parse request body
         $body = $request->getBody();
         if ($body === null) {
             return $this->createErrorResponse('invalid_request', 'Missing request body', 400);
         }
 
         parse_str($body, $params);
         $grantType = $params['grant_type'] ?? null;
 
         if (!$grantType) {
             return $this->createErrorResponse('invalid_request', 'Missing grant_type', 400);
         }
 
         // Check if grant type is supported
         if (!$this->config->isGrantTypeSupported($grantType)) {
             return $this->createErrorResponse('unsupported_grant_type', 'Grant type not supported', 400);
         }
 
         // Extract client credentials
         $clientCredentials = $this->extractClientCredentials($request, $params);
         if (!$clientCredentials) {
             return $this->createErrorResponse('invalid_client', 'Client authentication failed', 401);
         }
 
         [$clientId, $clientSecret] = $clientCredentials;
 
         // Validate client
         if (!$this->clientStore->validateCredentials($clientId, $clientSecret)) {
             return $this->createErrorResponse('invalid_client', 'Client authentication failed', 401);
         }
 
         // Check if client is allowed to use this grant type
         if (!$this->clientStore->isGrantTypeAllowed($clientId, $grantType)) {
             return $this->createErrorResponse('unauthorized_client', 'Client not authorized for this grant type', 400);
         }
 
         // Handle specific grant types
         switch ($grantType) {
             case 'authorization_code':
                 return $this->handleAuthorizationCodeGrant($clientId, $params);
             case 'client_credentials':
                 return $this->handleClientCredentialsGrant($clientId, $params);
             case 'refresh_token':
                 return $this->handleRefreshTokenGrant($clientId, $params);
             default:
                 return $this->createErrorResponse('unsupported_grant_type', 'Grant type not implemented', 400);
         }
     }
 
     /**
      * Handle authorization code grant.
      *
      * @param string $clientId Client ID
      * @param array $params Request parameters
      * @return HttpMessage HTTP response
      */
     private function handleAuthorizationCodeGrant(string $clientId, array $params): HttpMessage
     {
         $code = $params['code'] ?? null;
         $redirectUri = $params['redirect_uri'] ?? null;
         $codeVerifier = $params['code_verifier'] ?? null;
 
         if (!$code || !$redirectUri) {
             return $this->createErrorResponse('invalid_request', 'Missing required parameters', 400);
         }
 
         // Validate authorization code
         $codeMetadata = $this->tokenManager->validateAuthorizationCode(
             $code,
             $clientId,
             $redirectUri,
             $codeVerifier
         );
 
         if ($codeMetadata === null) {
             return $this->createErrorResponse('invalid_grant', 'Invalid authorization code', 400);
         }
 
         // Create tokens
         $scope = $codeMetadata['scope'] ?? null;
         $userId = $codeMetadata['user_id'] ?? null;
 
         $tokenData = $this->tokenManager->createAccessToken(
             $clientId,
             $userId,
             $scope,
             'authorization_code'
         );
 
         // Add refresh token if supported
         if (in_array('refresh_token', $this->config->getGrantTypes(), true)) {
             $refreshToken = $this->tokenManager->createRefreshToken(
                 $clientId,
                 $userId,
                 $scope,
                 $tokenData['access_token']
             );
             $tokenData['refresh_token'] = $refreshToken;
         }
 
         $this->logger->info('Tokens issued for authorization code grant', [
             'client_id' => $clientId,
             'user_id' => $userId
         ]);
 
         return HttpMessage::createJsonResponse($tokenData, 200);
     }
 
     /**
      * Handle client credentials grant.
      *
      * @param string $clientId Client ID
      * @param array $params Request parameters
      * @return HttpMessage HTTP response
      */
     private function handleClientCredentialsGrant(string $clientId, array $params): HttpMessage
     {
         $scope = $params['scope'] ?? null;
 
         // Create access token (no user ID for client credentials)
         $tokenData = $this->tokenManager->createAccessToken(
             $clientId,
             null,
             $scope,
             'client_credentials'
         );
 
         // Client credentials grant doesn't issue refresh tokens
         
         $this->logger->info('Token issued for client credentials grant', [
             'client_id' => $clientId
         ]);
 
         return HttpMessage::createJsonResponse($tokenData, 200);
     }
 
     /**
      * Handle refresh token grant.
      *
      * @param string $clientId Client ID
      * @param array $params Request parameters
      * @return HttpMessage HTTP response
      */
     private function handleRefreshTokenGrant(string $clientId, array $params): HttpMessage
     {
         $refreshToken = $params['refresh_token'] ?? null;
         $scope = $params['scope'] ?? null;
 
         if (!$refreshToken) {
             return $this->createErrorResponse('invalid_request', 'Missing refresh token', 400);
         }
 
         $tokenData = $this->tokenManager->refreshAccessToken(
             $refreshToken,
             $clientId,
             $scope
         );
 
         if ($tokenData === null) {
             return $this->createErrorResponse('invalid_grant', 'Invalid refresh token', 400);
         }
 
         $this->logger->info('Token refreshed', ['client_id' => $clientId]);
 
         return HttpMessage::createJsonResponse($tokenData, 200);
     }
 
     /**
      * Extract client credentials from request.
      *
      * @param HttpMessage $request HTTP request
      * @param array $params Request parameters
      * @return array|null [client_id, client_secret] or null
      */
     private function extractClientCredentials(HttpMessage $request, array $params): ?array
     {
         // Try Authorization header first (client_secret_basic)
         $authHeader = $request->getHeader('Authorization');
         if ($authHeader !== null && str_starts_with($authHeader, 'Basic ')) {
             $credentials = base64_decode(substr($authHeader, 6));
             if ($credentials !== false && str_contains($credentials, ':')) {
                 [$clientId, $clientSecret] = explode(':', $credentials, 2);
                 return [$clientId, $clientSecret];
             }
         }
 
         // Try request body (client_secret_post)
         if (isset($params['client_id'])) {
             $clientId = $params['client_id'];
             $clientSecret = $params['client_secret'] ?? null;
             
             // Check if this is a public client
             $client = $this->clientStore->getClient($clientId);
             if ($client !== null && ($client['client_type'] ?? 'confidential') === 'public') {
                 // Public clients don't have secrets
                 return [$clientId, null];
             }
             
             return [$clientId, $clientSecret];
         }
 
         return null;
     }
 
     /**
      * Authenticate user from request.
      *
      * @param HttpMessage $request HTTP request
      * @return string|null User ID or null if not authenticated
      */
     private function authenticateUser(HttpMessage $request): ?string
     {
         // This is a placeholder implementation
         // In a real system, this would check session, cookies, etc.
         // For MCP servers, authentication might be handled externally
         
         // For now, return null to trigger authentication page
         return null;
     }
 
     /**
      * Create authentication page HTML.
      *
      * @param HttpMessage $request Original request
      * @return HttpMessage HTTP response with authentication page
      */
     private function createAuthenticationPage(HttpMessage $request): HttpMessage
     {
         $html = <<<HTML
 <!DOCTYPE html>
 <html>
 <head>
     <title>Authorization Required</title>
     <style>
         body { font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
         .error { color: red; margin: 20px 0; }
     </style>
 </head>
 <body>
     <h1>Authorization Required</h1>
     <p>This MCP server requires authentication. Please implement your authentication mechanism.</p>
     <p class="error">Authentication not implemented in this example.</p>
 </body>
 </html>
 HTML;
 
         return HttpMessage::createTextResponse($html, 200)
             ->setHeader('Content-Type', 'text/html');
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
      * Create authorization error response with redirect.
      *
      * @param string $redirectUri Redirect URI
      * @param string $error Error code
      * @param string $description Error description
      * @param string|null $state State parameter
      * @return HttpMessage HTTP response
      */
     private function createAuthorizationErrorResponse(
         string $redirectUri,
         string $error,
         string $description,
         ?string $state
     ): HttpMessage {
         $params = [
             'error' => $error,
             'error_description' => $description
         ];
 
         if ($state !== null) {
             $params['state'] = $state;
         }
 
         $redirectUrl = $redirectUri . '?' . http_build_query($params);
 
         return HttpMessage::createEmptyResponse(302)
             ->setHeader('Location', $redirectUrl);
     }
 
     /**
      * Get token manager instance.
      *
      * @return TokenManager
      */
     public function getTokenManager(): TokenManager
     {
         return $this->tokenManager;
     }
 }