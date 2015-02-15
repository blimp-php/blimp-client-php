<?php
namespace Blimp;

class BlimpResponse {
    private $request;

    private $_status;
    private $_headers;

    private $_body;

    private $_data;

    private $_etag;
    private $_etag_hit;

    public function __construct($request, $status, $headers, $_body, $_etag = null) {
        $this->request = $request;

        $this->_status = $status;
        $this->_headers = $headers;

        $this->_body = $_body;

        $decodedResult = json_decode($this->_body, true);
        if ($decodedResult === null) {
            $decodedResult = array();
            parse_str($result, $decodedResult);
        }

        $this->_data = $decodedResult;

        $this->_etag_hit = $_etag !== null && $this->_status == 304;

        if($this->_etag_hit) {
          $this->_etag = $_etag;
        } else {
          $this->_etag = isset($headers['ETag']) ? $headers['ETag'] : null;
        }
    }

    public function getRequest() {
        return $this->request;
    }

    public function getData() {
        return $this->_data;
    }

    public function getBody() {
        return $this->_body;
    }

    public function isETagHit() {
        return $this->_etag_hit;
    }

    public function getETag() {
        return $this->_etag;
    }

    public function getPage($direction) {
        if (isset($this->_data->paging->$direction)) {
            $url = parse_url($this->_data->paging->$direction);
            parse_str($url['query'], $params);

            return new BlimpRequest(
                $this->request->getSession(),
                $this->request->getMethod(),
                $this->request->getPath(),
                $params
            );
        } else {
            return null;
        }
    }
}
