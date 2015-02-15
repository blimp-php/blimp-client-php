<?php
namespace Blimp;

use Blimp\BlimpRequest;
use Blimp\BlimpRequestException;

class AccessToken {
    /**
     * The access token.
     *
     * @var string
     */
    protected $accessToken;

    /**
     * Date when token expires.
     *
     * @var \DateTime|null
     */
    protected $expiresAt;

    /**
     * A unique ID to identify a client.
     *
     * @var string
     */
    protected $machineId;

    /**
     * Create a new access token entity.
     *
     * @param string $accessToken
     * @param int $expiresAt
     * @param string|null machineId
     */
    public function __construct($accessToken, $expiresAt = 0, $machineId = null) {
        $this->accessToken = $accessToken;
        if ($expiresAt) {
            $this->setExpiresAtFromTimeStamp($expiresAt);
        }
        $this->machineId = $machineId;
    }

    /**
     * Setter for expires_at.
     *
     * @param int $timeStamp
     */
    protected function setExpiresAtFromTimeStamp($timeStamp) {
        $dt = new \DateTime();
        $dt->setTimestamp($timeStamp);
        $this->expiresAt = $dt;
    }

    /**
     * Getter for expiresAt.
     *
     * @return \DateTime|null
     */
    public function getExpiresAt() {
        return $this->expiresAt;
    }

    /**
     * Getter for machineId.
     *
     * @return string|null
     */
    public function getMachineId() {
        return $this->machineId;
    }

    /**
     * Ensures the provided session info array is valid,
     *   throwing an exception if not.  Ensures the appId matches,
     *   that the machineId matches if it's being used,
     *   that the token is valid and has not expired.
     *
     * @param array $tokenInfo
     * @param string|null $appId Application ID to use
     * @param string|null $machineId
     *
     * @return boolean
     */
    public static function validateAccessToken(array $tokenInfo,
        $appId = null, $machineId = null) {

        $appIdIsValid = $tokenInfo->getAppId() == $appId;
        $machineIdIsValid = $tokenInfo->getProperty('machine_id') == $machineId;
        $accessTokenIsValid = $tokenInfo->isValid();

        if ($tokenInfo->getExpiresAt() instanceof \DateTime) {
            $accessTokenIsStillAlive = $tokenInfo->getExpiresAt()->getTimestamp() >= time();
        } else {
            $accessTokenIsStillAlive = true;
        }

        return $appIdIsValid && $machineIdIsValid && $accessTokenIsValid && $accessTokenIsStillAlive;
    }

    /**
     * Get a valid access token from a code.
     *
     * @param string $code
     * @param string|null $appId
     * @param string|null $appSecret
     * @param string|null $machineId
     *
     * @return AccessToken
     */
    public static function requestAccessTokenFromCode($code, $appId = null, $appSecret = null, $machineId = null) {
        $params = array(
            'code' => $code,
            'redirect_uri' => '',
        );

        if ($machineId) {
            $params['machine_id'] = $machineId;
        }

        return static::requestAccessToken($params, $appId, $appSecret);
    }

    /**
     * Request an access token based on a set of params.
     *
     * @param array $params
     * @param string|null $appId
     * @param string|null $appSecret
     *
     * @return AccessToken
     *
     * @throws BlimpRequestException
     */
    public static function requestAccessToken(array $params, $appId = null, $appSecret = null) {
        $response = static::request('/oauth/access_token', $params, $appId, $appSecret);
        $data = $response->getResponse();

        if (isset($data->access_token)) {
            $expiresAt = isset($data->expires_in) ? time() + $data->expires_in : 0;
            $machineId = isset($data->machine_id) ? (string) $data->machine_id : null;

            return new static($data->access_token, $expiresAt, $machineId);
        }

        throw BlimpRequestException::create(
            $response->getRawResponse(),
            $data,
            401
        );
    }

    /**
     * Request a code from a access token.
     *
     * @param array $params
     * @param string|null $appId
     * @param string|null $appSecret
     *
     * @return string
     *
     * @throws BlimpRequestException
     */
    public static function requestCode(array $params, $appId = null, $appSecret = null) {
        $response = static::request('/oauth/client_code', $params, $appId, $appSecret);
        $data = $response->getResponse();

        if (isset($data->code)) {
            return (string) $data->code;
        }

        throw BlimpRequestException::create(
            $response->getRawResponse(),
            $data,
            401
        );
    }

    /**
     * Send a request to Graph with an app access token.
     *
     * @param string $endpoint
     * @param array $params
     * @param string|null $appId
     * @param string|null $appSecret
     *
     * @return \Blimp\BlimpResponse
     *
     * @throws BlimpRequestException
     */
    protected static function request($endpoint, array $params, $appId = null, $appSecret = null) {
        if (!isset($params['client_id'])) {
            $params['client_id'] = $appId;
        }
        if (!isset($params['client_secret'])) {
            $params['client_secret'] = $appSecret;
        }

        // The response for this endpoint is not JSON, so it must be handled
        //   differently, not as a GraphObject.
        $request = new BlimpRequest(
            BlimpClient::newAppSession($appId, $appSecret),
            'GET',
            $endpoint,
            $params
        );
        return $request->execute();
    }

    /**
     * Get more info about an access token.
     *
     * @param string|null $appId
     * @param string|null $appSecret
     *
     * @return GraphSessionInfo
     */
    public function getInfo($appId = null, $appSecret = null) {
        $params = array('input_token' => $this->accessToken);

        $request = new BlimpRequest(
            BlimpClient::newAppSession($appId, $appSecret),
            'GET',
            '/debug_token',
            $params
        );
        $response = $request->execute();

        // Update the data on this token
        if (isset($data['expires_at'])) {
            $this->expiresAt = $data['expires_at'];
        }

        return $response;
    }

    /**
     * Returns the access token as a string.
     *
     * @return string
     */
    public function __toString() {
        return $this->accessToken;
    }
}
