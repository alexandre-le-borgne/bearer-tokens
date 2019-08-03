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


use Psr\Http\Message\ServerRequestInterface;
use UnexpectedValueException;

/**
 * Class UriQueryParameter
 * @package OAuth2\AuthenticationMethods
 *
 *  When sending the access token in the HTTP request URI, the client
 * adds the access token to the request URI query component as defined
 * by "Uniform Resource Identifier (URI): Generic Syntax" [RFC3986],
 * using the "access_token" parameter.
 *
 * For example, the client makes the following HTTP request using
 * transport-layer security:
 *
 * GET /resource?access_token=mF_9.B5f-4.1JqM HTTP/1.1
 * Host: server.example.com
 *
 * The HTTP request URI query can include other request-specific
 * parameters, in which case the "access_token" parameter MUST be
 * properly separated from the request-specific parameters using "&"
 * character(s) (ASCII code 38).
 *
 * For example:
 *
 * https://server.example.com/resource?access_token=mF_9.B5f-4.1JqM&p=q
 *
 * Clients using the URI Query Parameter method SHOULD also send a
 * Cache-Control header containing the "no-store" option.  Server
 * success (2XX status) responses to these requests SHOULD contain a
 * Cache-Control header with the "private" option.
 *
 * Because of the security weaknesses associated with the URI method
 * (see Section 5), including the high likelihood that the URL
 * containing the access token will be logged, it SHOULD NOT be used
 * unless it is impossible to transport the access token in the
 * "Authorization" request header field or the HTTP request entity-body.
 * Resource servers MAY support this method.
 *
 * This method is included to document current use; its use is not
 * recommended, due to its security deficiencies (see Section 5) and
 * also because it uses a reserved query parameter name, which is
 * counter to URI namespace best practices, per "Architecture of the
 * World Wide Web, Volume One" [W3C.REC-webarch-20041215].
 */
class UriQueryParameter
{
    public function supports(ServerRequestInterface $request): bool
    {
        return !empty($request->getQueryParams()['access_token']);
    }

    public function getToken(ServerRequestInterface $request): string
    {
        return $request->getQueryParams()['access_token'];
    }
}