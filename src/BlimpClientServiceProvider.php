<?php
namespace Blimp\Client;

use Pimple\Container;
use Pimple\ServiceProviderInterface;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;

use GuzzleHttp\Client;

class BlimpClientServiceProvider implements ServiceProviderInterface {
    public function register(Container $api) {
        $api['client.backend_url'] = '';
        $api['client.client_id'] = '';
        $api['client.client_secret'] = null;
        $api['client.redirect_uri'] = '';
        $api['client.scope'] = null;

        $api['client.authorization_endpoint'] = '/oauth/authorize';
        $api['client.token_endpoint'] = '/oauth/token';
        $api['client.code_endpoint'] = '/oauth/code';
        $api['client.verify_endpoint'] = '/oauth/verify-credentials';

        $api['client.certificate'] = true;

        $api['client.http_client'] = function () {
            return new Client();
        };

        $api['client.access_token'] = $api->protect(function () use ($api) {
            if($api['http.session']->has('access_token')) {
                return $api['http.session']->get('access_token');
            }

            return null;
        });

        $api['client.request_code'] = $api->protect(function ($context, $error = null, $error_description = null) use ($api) {
            $state = $api['client.random'](16);
            $api['http.session']->set('state_'.$state, $context);
            $params = array(
              'state' => $state,
              'response_type' => 'code',
              'client_id' => $api['client.client_id']
            );

            $redirect_uri = $api['client.redirect_uri'];
            if (parse_url($redirect_uri, PHP_URL_SCHEME) === null) {
                $redirect_uri = $redirect_uri;
            }

            $params['redirect_uri'] = $redirect_uri;

            if (!empty($api['client.scope'])) {
                $params['scope'] = $api['client.scope'];
            }

            if (!empty($error)) {
                $params['error'] = $error;
            }

            if (!empty($error_description)) {
                $params['error_description'] = $error_description;
            }

            return $api['client.backend_url'] . $api['client.authorization_endpoint'] . '?' . http_build_query($params, null, '&');
        });

        $api['client.session_from_code'] = $api->protect(function ($code, $state, $out_error = null, $out_erro_description = null) use ($api) {
            $context = null;
            $error = '';
            $error_description = '';

            if (!empty($state)) {
                if ($api['http.session']->has('state_' . $state)) {
                    $context = $api['http.session']->get('state_' . $state);
                    $api['http.session']->remove('state_' . $state);

                    if (!empty($code)) {
                        $response_data = $api['client.token_from_code']($code);

                        if(!empty($response_data) && is_array($response_data)) {
                            if (array_key_exists('access_token', $response_data)) {
                                $api['http.session']->set('access_token', $response_data);

                                return array_key_exists('return_to', $context) ? $context['return_to'] : '/';
                            } else if (array_key_exists('error', $response_data)) {
                                $error = $response_data['error'];
                                if (array_key_exists('error_description', $response_data)) {
                                    $error_description = $response_data['error_description'];
                                }
                            }
                        } else {
                            $error = 'server_error';
                            $error_description = 'Unknown error. Empty response.';
                        }
                    } else if (!empty($out_error)) {
                        $error = $out_error;
                        if (!empty($out_erro_description)) {
                            $error_description = $out_erro_description;
                        }
                    }
                } else {
                    $error = 'csrf_prevention';
                    $error_description = 'Invalid local state.';
                }
            } else {
                $error = 'csrf_prevention';
                $error_description = 'Missing local state.';
            }

            $api['http.session']->remove('access_token');

            return $api['client.request_code']($context, $error, $error_description);
        });

        $api['client.token_from_code'] = $api->protect(function ($code) use ($api) {
            $payload = [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $api['client.redirect_uri']
            ];

            $auth = [$api['client.client_id'], $api['client.client_secret']];

            $response = $api['client.request']('POST', $api['client.token_endpoint'], null, $payload, $auth);

            return $response['data'];
        });

        $api['client.validate_access_token'] = $api->protect(function ($access_token, $include_entities = false) use ($api) {
            $parameters = [
                'input_token' => $access_token['access_token'],
                'redirect_uri' => $api['client.redirect_uri'],
                'include_entities' => $include_entities
            ];

            $auth = [$api['client.client_id'], $api['client.client_secret']];

            $response = $api['client.request']('GET', $api['client.verify_endpoint'], $parameters, null, $auth);

            return $response['status'] == 200 ? $response['data'] : false;
        });

        $api['client.request'] = $api->protect(function ($method, $url, $parameters = null, $payload = null, $auth = null, $etag = null) use ($api) {
            if (strpos($url, '?') !== false) {
                $uri_query = array();
                $parameters = $parameters ?: array();

                $parts = explode('?', $url, 2);
                parse_str($parts[1], $uri_query);

                $parameters = array_merge($parameters, $uri_query);

                $url = $parts[0];
            }

            if (parse_url($url, PHP_URL_SCHEME) === null) {
                $url = $api['client.backend_url'] . $url;
            }

            $headers = array();

            $headers['User-Agent'] = 'blimp-client-php';
            $headers['Accept-Encoding'] = '*';

            if (empty($auth)) {
                $access_token = $api['client.access_token']();

                if (!empty($access_token)) {
                    $headers['Authorization'] = $access_token['token_type'] . ' ' . $access_token['access_token'];

                    $client_secret = $api['client.client_secret'];
                    if (!empty($client_secret)) {
                        $headers['Authorization-Proof'] = hash_hmac('sha256', $access_token['access_token'], $client_secret);
                    }
                }
            }

            if (!empty($etag)) {
                $headers['If-None-Match'] = $etag;
            }

            $options = array();

            if ($headers) {
                $options['headers'] = $headers;
            }

            if (!empty($parameters)) {
                $options['query'] = $parameters;
            }

            if (!empty($payload)) {
                $options['json'] = $payload;
            }

            if (!empty($auth)) {
                $options['auth'] = $auth;
            }

            // $options['debug'] = true;

            $cert = $api['client.certificate'];
            if (!empty($cert)) {
                $options['verify'] = $cert;
            }

            $options['exceptions'] = false;

            $request = $api['client.http_client']->createRequest($method, $url, $options);
            $response = $api['client.http_client']->send($request);

            $response_status = $response->getStatusCode();
            $response_headers = $response->getHeaders();
            $response_body = $response->getBody();

            $response_data = json_decode($response_body, true);
            if ($response_data === null) {
                $response_data = array();
                parse_str($response_body, $response_data);
            }

            $etag_hit = !empty($etag) && $response_status == 304;

            if($etag_hit) {
              $response_etag = $etag;
            } else {
              $response_etag = isset($response_headers['ETag']) ? $response_headers['ETag'] : null;
            }

            return [
                'status' => $response_status,
                'headers' => $response_headers,
                'body' => $response_body,
                'data' => $response_data,
                'etag' => $response_etag,
                'etag_hit' => $etag_hit
            ];
        });

        $api['client.random'] = $api->protect(function ($bytes) {
            $buf = '';
            // http://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/
            if (!ini_get('open_basedir')
                && is_readable('/dev/urandom')) {
                $fp = fopen('/dev/urandom', 'rb');
                if ($fp !== FALSE) {
                    $buf = fread($fp, $bytes);
                    fclose($fp);
                    if ($buf !== FALSE) {
                        return bin2hex($buf);
                    }
                }
            }

            if (function_exists('mcrypt_create_iv')) {
                $buf = mcrypt_create_iv($bytes, MCRYPT_DEV_URANDOM);
                if ($buf !== FALSE) {
                    return bin2hex($buf);
                }
            }

            while (strlen($buf) < $bytes) {
                $buf .= md5(uniqid(mt_rand(), true), true);
                // We are appending raw binary
            }

            return bin2hex(substr($buf, 0, $bytes));
        });


        $api->extend('blimp.extend', function ($status, $api) {
            if($status) {
                if ($api->offsetExists('config.root')) {
                    $api->extend('config.root', function ($root, $api) {
                        $tb = new TreeBuilder();

                        $rootNode = $tb->root('blimp_client');

                        $rootNode
                            ->canBeEnabled()
                            ->children()
                                ->scalarNode('backend_url')->cannotBeEmpty()->end()
                                ->scalarNode('client_id')->cannotBeEmpty()->end()
                                ->scalarNode('client_secret')->end()
                                ->scalarNode('redirect_uri')->end()
                                ->scalarNode('scope')->end()

                                ->variableNode('certificate')->defaultValue(true)->end()

                                ->scalarNode('authorization_endpoint')->end()
                                ->scalarNode('token_endpoint')->end()
                                ->scalarNode('code_endpoint')->end()
                                ->scalarNode('verify_endpoint')->end()
                            ->end()
                        ;

                        $root->append($rootNode);

                        return $root;
                    });
                }
            }

            $api->extend('blimp.init', function ($status, $api) {
                if ($status) {
                    if ($api->offsetExists('config')) {
                        if($api['config']['blimp_client']['enabled']) {
                            $client_config = $api['config']['blimp_client'];

                            $api['client.backend_url'] = $client_config['backend_url'];
                            $api['client.client_id'] = $client_config['client_id'];
                            if(array_key_exists('client_secret', $client_config) && !empty($client_config['client_secret'])) {
                                $api['client.client_secret'] = $client_config['client_secret'];
                            } else {
                                $api['client.client_secret'] = null;
                            }
                            if(array_key_exists('redirect_uri', $client_config)) {
                                $api['client.redirect_uri'] = $client_config['redirect_uri'];
                            } else {
                                $api['client.redirect_uri'] = '';
                            }
                            if(array_key_exists('scope', $client_config) && !empty($client_config['scope'])) {
                                $api['client.scope'] = $client_config['scope'];
                            } else {
                                $api['client.scope'] = null;
                            }

                            if(array_key_exists('certificate', $client_config)) {
                                $api['client.certificate'] = $client_config['certificate'];
                            }

                            if(array_key_exists('authorization_endpoint', $client_config)) {
                                $api['client.authorization_endpoint'] = $client_config['authorization_endpoint'];
                            }

                            if(array_key_exists('token_endpoint', $client_config)) {
                                $api['client.token_endpoint'] = $client_config['token_endpoint'];
                            }

                            if(array_key_exists('code_endpoint', $client_config)) {
                                $api['client.code_endpoint'] = $client_config['code_endpoint'];
                            }

                            if(array_key_exists('verify_endpoint', $client_config)) {
                                $api['client.verify_endpoint'] = $client_config['verify_endpoint'];
                            }
                        }
                    }
                }

                return $status;
            });

            return $status;
        });
    }
}
