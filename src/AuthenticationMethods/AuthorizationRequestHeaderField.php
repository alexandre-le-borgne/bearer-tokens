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

namespace OAuth2\AuthenticationMethods;


use http\Exception\UnexpectedValueException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class AuthorizationRequestHeaderField
 * @package OAuth2\AuthenticationMethods
 *
 * When sending the access token in the "Authorization" request header
 * field defined by HTTP/1.1 [RFC2617], the client uses the "Bearer"
 * authentication scheme to transmit the access token.
 *
 * For example:
 *
 * GET /resource HTTP/1.1
 * Host: server.example.com
 * Authorization: Bearer mF_9.B5f-4.1JqM
 *
 * The syntax of the "Authorization" header field for this scheme
 * follows the usage of the Basic scheme defined in Section 2 of
 * [RFC2617].  Note that, as with Basic, it does not conform to the
 * generic syntax defined in Section 1.2 of [RFC2617] but is compatible
 * with the general authentication framework being developed for
 * HTTP 1.1 [HTTP-AUTH], although it does not follow the preferred
 * practice outlined therein in order to reflect existing deployments.
 * The syntax for Bearer credentials is as follows:
 *
 * b64token    = 1*( ALPHA / DIGIT /
 * "-" / "." / "_" / "~" / "+" / "/" ) *"="
 * credentials = "Bearer" 1*SP b64token
 *
 * Clients SHOULD make authenticated requests with a bearer token using
 * the "Authorization" request header field with the "Bearer" HTTP
 * authorization scheme.  Resource servers MUST support this method.
 */
class AuthorizationRequestHeaderField
{
    public function supports(ServerRequestInterface $request): bool
    {
        return $request->hasHeader('authorization');
    }

    public function getToken(ServerRequestInterface $request): string
    {
        $authorization = $request->getHeader('authorization')[0] ?? null;
        if (!$authorization) {
            throw new UnexpectedValueException('Invalid authorization header');
        }

        $parts = explode(' ', $authorization);
        if (count($parts) !== 2) {
//            invalid_request
//         The request is missing a required parameter, includes an
//         unsupported parameter or parameter value, repeats the same
//         parameter, uses more than one method for including an access
//            token, or is otherwise malformed.  The resource server SHOULD
//         respond with the HTTP 400 (Bad Request) status code.
            throw new UnexpectedValueException('Invalid authorization header');
        }

        if ($parts[0] !== 'Bearer') {
            throw new UnexpectedValueException('Invalid authorization header');
        }

        return $parts[1];
    }
}