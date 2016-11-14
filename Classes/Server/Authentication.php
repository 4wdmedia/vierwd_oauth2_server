<?php
namespace Vierwd\VierwdOAuth2Server\Server;

use TYPO3\CMS\Core\Utility\GeneralUtility;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use Vierwd\VierwdOAuth2Server\Repositories;
use Vierwd\VierwdOAuth2Server\Entities;

class Authentication extends \TYPO3\CMS\Sv\AbstractAuthenticationService {

	public function oauth2Server(ServerRequestInterface $request, ResponseInterface $response) {
		$action = GeneralUtility::_GP('action');

		if ($action === 'authorize') {
			return $this->respondToAuthorize($request, $response);
		}

		if ($action === 'token') {
			return $this->respondToAccessToken($request, $response);
		}

		if ($action === 'resource') {
			return $this->respondToOwnerResource($request, $response);
		}

		// fsmir('Unknown action: ' . $action);
	}

	/**
	 * @return League\OAuth2\Server\AuthorizationServer
	 */
	public function getOAuth2Server() {
		$clientRepository = new Repositories\ClientRepository();
		$scopeRepository = new Repositories\ScopeRepository();
		$accessTokenRepository = new Repositories\AccessTokenRepository();
		$authCodeRepository = new Repositories\AuthCodeRepository();
		$refreshTokenRepository = new Repositories\RefreshTokenRepository();

		$privateKey = GeneralUtility::getFileAbsFileName('EXT:vierwd_oauth2_server/Resources/Private/Keys/private.key');
		$publicKey = GeneralUtility::getFileAbsFileName('EXT:vierwd_oauth2_server/Resources/Private/Keys/public.key');

		// Setup the authorization server
		$server = new \League\OAuth2\Server\AuthorizationServer(
			$clientRepository,
			$accessTokenRepository,
			$scopeRepository,
			$privateKey,
			$publicKey
		);
		// Enable the client credentials grant on the server
		// $server->enableGrantType(
		// 	new \League\OAuth2\Server\Grant\ClientCredentialsGrant(),
		// 	new \DateInterval('PT1H') // access tokens will expire after 1 hour
		// );

		// Enable the authentication code grant on the server with a token TTL of 1 hour
		$server->enableGrantType(
			new \League\OAuth2\Server\Grant\AuthCodeGrant(
				$authCodeRepository,
				$refreshTokenRepository,
				new \DateInterval('PT10M')
			),
			new \DateInterval('PT1H')
		);

		return $server;
	}


	public function respondToAuthorize(ServerRequestInterface $request, ResponseInterface $response) {
		$server = $this->getOAuth2Server();

		try {
			// Validate the HTTP request and return an AuthorizationRequest object.
			// The auth request object can be serialized into a user's session
			$authRequest = $server->validateAuthorizationRequest($request);
			// Once the user has logged in set the user on the AuthorizationRequest
			$authRequest->setUser(new Entities\UserEntity());
			// Once the user has approved or denied the client update the status
			// (true = approved, false = denied)
			$authRequest->setAuthorizationApproved(true);
			// Return the HTTP redirect response
			return $server->completeAuthorizationRequest($authRequest, $response);
		} catch (OAuthServerException $exception) {
			// All instances of OAuthServerException can be formatted into a HTTP response

			return $exception->generateHttpResponse($response);
		} catch (\Exception $exception) {
			// Unknown exception
			$body = new Stream('php://temp', 'r+');
			$body->write($exception->getMessage());
			return $response->withStatus(500)->withBody($body);
		}
	}

	public function respondToAccessToken(ServerRequestInterface $request, ResponseInterface $response) {
		$server = $this->getOAuth2Server();

		try {
			return $server->respondToAccessTokenRequest($request, $response);
		} catch (OAuthServerException $exception) {
			return $exception->generateHttpResponse($response);
		} catch (\Exception $exception) {
			$body = new Stream('php://temp', 'r+');
			$body->write($exception->getMessage());
			return $response->withStatus(500)->withBody($body);
		}
	}

	public function respondToOwnerResource(ServerRequestInterface $request, ResponseInterface $response) {
		$accessTokenRepository = new Repositories\AccessTokenRepository();
		$publicKey = GeneralUtility::getFileAbsFileName('EXT:vierwd_oauth2_server/Resources/Private/Keys/public.key');

		$server = new \League\OAuth2\Server\ResourceServer($accessTokenRepository, $publicKey);

		try {
			if (!$request->hasHeader('authorization') && isset($_SERVER['Authorization'])) {
				$request = $request->withAddedHeader('Authorization', $_SERVER['Authorization']);
			}
			$request = $server->validateAuthenticatedRequest($request);
		} catch (OAuthServerException $exception) {
			fsmir('incoming', $request, $response, $exception);
			return $exception->generateHttpResponse($response);
		} catch (\Exception $exception) {
			return (new OAuthServerException($exception->getMessage(), 0, 'unknown_error', 500))
				->generateHttpResponse($response);
		}

		$response->getBody()->write(json_encode([
			'name' => 'rvock',
			'realName' => 'Robert Vock',
			'email' => 'robert.vock@4wdmedia.de',
		]));
		return $response->withStatus(200);
	}
}