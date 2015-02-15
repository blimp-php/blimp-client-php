<?php
namespace Blimp;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\AdapterException;
use GuzzleHttp\Exception\RequestException;

class BlimpRequest {
    private static $guzzleClient;

    private $_headers;
    private $_method;
    private $_uri;
    private $_query;
    private $_data;

    private $_etag;

    private $_access_token;
    private $_client_secret;

    public function __construct($client, $method, $uri, $parameters = null, $data = null, $etag = null) {
        static::$guzzleClient = static::$guzzleClient ?: new Client();

        $this->_method = $method;

        if (strpos($uri, '?') === false) {
            $this->_uri = $uri;
        } else {
            $uri_query = array();
            $parameters = $parameters ?: array();

            $parts = explode('?', $url, 2);
            parse_str($parts[1], $uri_query);

            $parameters = array_merge($parameters, $uri_query);

            $this->_uri = $parts[0];
        }

        $this->_query = $parameters;

        $this->_data = $data;

        $this->_etag = $etag;

        $this->_access_token = $client->getAccessToken();
        $this->_client_secret = $client->getClientSecret();
    }

    public function execute() {
        $this->_headers = array();

        $this->_headers['User-Agent'] = 'blimp-client-php-' . BlimpClient::VERSION;
        $this->_headers['Accept-Encoding'] = '*';

        if (isset($this->_access_token)) {
            $this->_headers['Authorization'] = $this->_access_token;

            if (isset($this->_client_secret)) {
                $this->_headers['Authorization-Proof'] = hash_hmac('sha256', $this->_access_token, $this->_client_secret);
            }
        }

        if (isset($this->_etag)) {
            $this->_headers['If-None-Match'] = $this->_etag;
        }

        $options = array();

        if ($this->_headers) {
            $options['headers'] = $this->_headers;
        }

        if ($this->_query) {
            $options['query'] = $this->_query;
        }

        if ($this->_data) {
            $options['json'] = $this->_data;
        }

        if(this->_cert) {
            $options['verify'] = this->_cert;
        }

        $request = self::$guzzleClient->createRequest($this->_method, $url, $options);

        try {
            $response = self::$guzzleClient->send($request);
        } catch (RequestException $e) {
            $response = $e->getResponse();
        }

        return new BlimpResponse($this, $response->getStatusCode(), $response->getHeaders(), $response->getBody(), $_etag);
    }
}
