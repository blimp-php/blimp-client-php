<?php
namespace Blimp;

class BlimpClient {
    public static const VERSION = '0.1.0';

    private $_base_endpoint = 'https:/localhost';
    private $_ssl_verify_cert = null;

    private $_auth_endpoint = '/oauth/authorize';
    private $_token_endpoint = '/oauth/token';
    private $_verify_endpoint = '/oauth/verify-credentials';

    private $_client_id;
    private $_client_secret;

    private $_access_token;
    private $_signed_request;

    private function __construct($access_token, SignedRequest $signed_request = null) {
        $this->_access_token = $access_token instanceof AccessToken ? $access_token : new AccessToken($access_token);
        $this->_signed_request = $signed_request;
    }

    public function getAccessToken() {
        return $this->_access_token;
    }

    public function getSignedRequest() {
        return $this->_signed_request;
    }

    public static function sessionFromAccessToken($access_token) {
        return new static($access_token);
    }

    public static function sessionFromSignedRequest(SignedRequest $signed_request) {
        $access_token = null;

        if ($signed_request->get('code') && !$signed_request->get('oauth_token')) {
          $code = $signed_request->get('code');
          $access_token = access_token::getAccessTokenFromCode($code);
        } else {
          $access_token = $signed_request->get('oauth_token');
          $expiresAt = $signed_request->get('expires', 0);

          $access_token = new AccessToken($access_token, $expiresAt);
        }

        return new static($access_token, $signed_request);
    }

    public static function sessionFromClientCredentials($client_id = null, $client_secret = null) {
        $targetclient_id = static::_getTargetclient_id($client_id);
        $targetclient_secret = static::_getTargetclient_secret($client_secret);
        return new static(
            $targetclient_id . '|' . $targetclient_secret
        );
    }
}
