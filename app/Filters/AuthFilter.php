<?php

namespace App\Filters;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Filters\FilterInterface;

class AuthFilter implements FilterInterface
{
    /**
     * Do whatever processing this filter needs to do.
     * By default it should not return anything during
     * normal execution. However, when an abnormal state
     * is found, it should return an instance of
     * CodeIgniter\HTTP\Response. If it does, script
     * execution will end and that Response will be
     * sent back to the client, allowing for error pages,
     * redirects, etc.
     *
     * @param RequestInterface $request
     * @param array|null       $arguments
     *
     * @return RequestInterface|ResponseInterface|string|void
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        // Function to get specific header(s)
        function getHeader($headerName = null)
        {
            $headers = [];

            // Loop through the $_SERVER superglobal
            foreach ($_SERVER as $key => $value) {
                // Check if the key starts with 'HTTP_'
                if (strpos($key, 'HTTP_') === 0) {
                    // Extract the header name
                    $headerName = str_replace('HTTP_', '', $key);
                    // Replace underscores with hyphens for standard header format
                    $headerName = str_replace('_', '-', $headerName);
                    // Add to the headers array
                    $headers[strtolower($headerName)] = $value;
                }
            }

            // Return all headers if no specific header is requested
            if ($headerName === null) {
                return $headers;
            }

            // Return the specific header if it exists
            $headerName = strtolower($headerName);
            return isset($headers[$headerName]) ? $headers[$headerName] : null;
        }


        $key = getenv('JWT_SECRET');
        $token = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';

        // check if token is null or empty
        if (is_null($token) || empty($token)) {

            $response = service('response');
            $response->setBody('Access denied');
            $response->setStatusCode(401);
            return $response;
        }

        try {
            // $decoded = JWT::decode($token, $key, array("HS256"));
            $decoded = JWT::decode($token, new Key($key, 'HS256'));
        } catch (Exception $ex) {

            $response = service('response');
            $response->setBody('Access denied');
            $response->setStatusCode(401);
            return $response;
        }
    }

    /**
     * Allows After filters to inspect and modify the response
     * object as needed. This method does not allow any way
     * to stop execution of other after filters, short of
     * throwing an Exception or Error.
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @param array|null        $arguments
     *
     * @return ResponseInterface|void
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        //
    }
}
