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


use Psr\Http\Message\ResponseInterface;

/**
 * Class ErrorMiddleware
 * @package OAuth2
 *
 * If the protected resource request does not include authentication
 * credentials or does not contain an access token that enables access
 * to the protected resource, the resource server MUST include the HTTP
 * "WWW-Authenticate" response header field; it MAY include it in
 * response to other conditions as well.  The "WWW-Authenticate" header
 * field uses the framework defined by HTTP/1.1 [RFC2617].
 *
 * All challenges defined by this specification MUST use the auth-scheme
 * value "Bearer".  This scheme MUST be followed by one or more
 * auth-param values.  The auth-param attributes used or defined by this
 * specification are as follows.  Other auth-param attributes MAY be
 * used as well.
 *
 * A "realm" attribute MAY be included to indicate the scope of
 * protection in the manner described in HTTP/1.1 [RFC2617].  The
 * "realm" attribute MUST NOT appear more than once.
 *
 * The "scope" attribute is defined in Section 3.3 of [RFC6749].  The
 * "scope" attribute is a space-delimited list of case-sensitive scope
 * values indicating the required scope of the access token for
 * accessing the requested resource. "scope" values are implementation
 * defined; there is no centralized registry for them; allowed values
 * are defined by the authorization server.  The order of "scope" values
 * is not significant.  In some cases, the "scope" value will be used
 * when requesting a new access token with sufficient scope of access to
 * utilize the protected resource.  Use of the "scope" attribute is
 * OPTIONAL.  The "scope" attribute MUST NOT appear more than once.  The
 * "scope" value is intended for programmatic use and is not meant to be
 * displayed to end-users.
 *
 * Two example scope values follow; these are taken from the OpenID
 * Connect [OpenID.Messages] and the Open Authentication Technology
 * Committee (OATC) Online Multimedia Authorization Protocol [OMAP]
 * OAuth 2.0 use cases, respectively:
 *
 * scope="openid profile email"
 * scope="urn:example:channel=HBO&urn:example:rating=G,PG-13"
 *
 * If the protected resource request included an access token and failed
 * authentication, the resource server SHOULD include the "error"
 * attribute to provide the client with the reason why the access
 * request was declined.  The parameter value is described in
 * Section 3.1.  In addition, the resource server MAY include the
 * "error_description" attribute to provide developers a human-readable
 * explanation that is not meant to be displayed to end-users.  It also
 * MAY include the "error_uri" attribute with an absolute URI
 * identifying a human-readable web page explaining the error.  The
 * "error", "error_description", and "error_uri" attributes MUST NOT
 * appear more than once.
 *
 * Values for the "scope" attribute (specified in Appendix A.4 of
 * [RFC6749]) MUST NOT include characters outside the set %x21 / %x23-5B
 * / %x5D-7E for representing scope values and %x20 for delimiters
 * between scope values.  Values for the "error" and "error_description"
 * attributes (specified in Appendixes A.7 and A.8 of [RFC6749]) MUST
 * NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.
 * Values for the "error_uri" attribute (specified in Appendix A.9 of
 * [RFC6749]) MUST conform to the URI-reference syntax and thus MUST NOT
 * include characters outside the set %x21 / %x23-5B / %x5D-7E.
 *
 * For example, in response to a protected resource request without
 * authentication:
 *
 * HTTP/1.1 401 Unauthorized
 * WWW-Authenticate: Bearer realm="example"
 *
 * And in response to a protected resource request with an
 * authentication attempt using an expired access token:
 *
 * HTTP/1.1 401 Unauthorized
 * WWW-Authenticate: Bearer realm="example",
 * error="invalid_token",
 * error_description="The access token expired"
 */
class ErrorMiddleware
{
    public function handle(ResponseInterface $response, array $scopes, ?OAuthErrorInterface $error = null): ResponseInterface
    {
        $data = [];
        if(!empty($scopes)) {
            $data['realm'] ='"'. implode(' ', $scopes) . '"';
        }

        if($error) {
            $data = array_merge($data, $error->toArray());
        }

        $response->withHeader('www-authenticate', 'Bearer' . ($data ? ' '.implode(', ', $data) : ''));
        return $response;
    }
}