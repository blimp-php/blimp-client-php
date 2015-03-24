<?php
namespace Blimp\Client\Rest;

use Pimple\Container;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

class SignOut {
    public function process(Container $api, Request $request) {
        $api['http.session']->remove('access_token');

        $response = new RedirectResponse('/');
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        $response->setPrivate();

        return $response;
    }
}
