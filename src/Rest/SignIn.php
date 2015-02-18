<?php
namespace Blimp\Client\Rest;

use Pimple\Container;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

class SignIn {
    public function process(Container $api, Request $request) {
        $query = $request->query->all();

        $code = array_key_exists('code', $query) ? $query['code'] : null;
        $state = array_key_exists('state', $query) ? $query['state'] : null;

        $error = array_key_exists('error', $query) ? $query['error'] : null;
        $error_description = array_key_exists('error_description', $query) ? $query['error_description'] : null;

        if(empty($error) || $error == 'invalid_grant') {
            $destination = $api['client.session_from_code']($code, $state, $error, $error_description);
        } else {
            $destination = '/error?error='.$error;
        }

        $response = new RedirectResponse($destination);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        $response->setPrivate();

        return $response;
    }
}
