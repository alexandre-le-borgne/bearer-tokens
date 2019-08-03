<?php
/**
 * php-guard/curl <https://github.com/php-guard/curl>
 * Copyright (C) 2019 by Alexandre Le Borgne <alexandre.leborgne.83@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace OAuth2;


use OAuth2\AuthenticationMethods\AuthorizationRequestHeaderField;
use OAuth2\AuthenticationMethods\FormEncodedBodyParameter;
use OAuth2\AuthenticationMethods\UriQueryParameter;
use Psr\Http\Message\ServerRequestInterface;

class Authenticator
{
    protected $authenticationMethods;

    public function __construct()
    {
        $this->authenticationMethods = [
            new AuthorizationRequestHeaderField(),
            new FormEncodedBodyParameter(),
            new UriQueryParameter()
        ];
    }

    public function authenticate(ServerRequestInterface $request): BearerTokenInterface
    {
        $supportedAuthenticationMethod = null;
        foreach ($this->authenticationMethods as $authenticationMethod) {
            if ($authenticationMethod->supports($request)) {
                if ($supportedAuthenticationMethod) {
                    throw new \LogicException('Multiple methods used');
                }

                $supportedAuthenticationMethod = $authenticationMethod;
            }
        }

        /*
         *
         *
   invalid_request
         The request is missing a required parameter, includes an
         unsupported parameter or parameter value, repeats the same
         parameter, uses more than one method for including an access
         token, or is otherwise malformed.  The resource server SHOULD
         respond with the HTTP 400 (Bad Request) status code.

   invalid_token
         The access token provided is expired, revoked, malformed, or
         invalid for other reasons.  The resource SHOULD respond with
         the HTTP 401 (Unauthorized) status code.  The client MAY
         request a new access token and retry the protected resource
         request.

   insufficient_scope
         The request requires higher privileges than provided by the
         access token.  The resource server SHOULD respond with the HTTP
         403 (Forbidden) status code and MAY include the "scope"
         attribute with the scope necessary to access the protected
         resource.

         */
        return $supportedAuthenticationMethod->getToken($request);
    }
}