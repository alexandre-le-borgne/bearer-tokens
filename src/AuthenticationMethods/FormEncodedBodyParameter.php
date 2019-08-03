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
 * Class FormEncodedBodyParameter
 * @package OAuth2\AuthenticationMethods
 *
 * When sending the access token in the HTTP request entity-body, the
 * client adds the access token to the request-body using the
 * "access_token" parameter.  The client MUST NOT use this method unless
 * all of the following conditions are met:
 *
 * o  The HTTP request entity-header includes the "Content-Type" header
 * field set to "application/x-www-form-urlencoded".
 *
 * o  The entity-body follows the encoding requirements of the
 * "application/x-www-form-urlencoded" content-type as defined by
 * HTML 4.01 [W3C.REC-html401-19991224].
 *
 * o  The HTTP request entity-body is single-part.
 *
 * o  The content to be encoded in the entity-body MUST consist entirely
 * of ASCII [USASCII] characters.
 *
 * o  The HTTP request method is one for which the request-body has
 * defined semantics.  In particular, this means that the "GET"
 * method MUST NOT be used.
 *
 * The entity-body MAY include other request-specific parameters, in
 * which case the "access_token" parameter MUST be properly separated
 * from the request-specific parameters using "&" character(s) (ASCII
 * code 38).
 *
 * For example, the client makes the following HTTP request using
 * transport-layer security:
 *
 * POST /resource HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * access_token=mF_9.B5f-4.1JqM
 *
 * The "application/x-www-form-urlencoded" method SHOULD NOT be used
 * except in application contexts where participating browsers do not
 * have access to the "Authorization" request header field.  Resource
 * servers MAY support this method.
 */
class FormEncodedBodyParameter
{
    public function supports(ServerRequestInterface $request): bool
    {
        return !empty($request->getParsedBody()['access_token']);
    }

    public function getToken(ServerRequestInterface $request): string
    {
        if ('application/x-www-form-urlencoded' !== $request->getHeader('content-type')[0] ?? null) {
            throw new UnexpectedValueException('Invalid request content type');
        }

        return $request->getParsedBody()['access_token'];
    }
}