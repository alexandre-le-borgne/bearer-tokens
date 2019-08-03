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

/**
 * Class BearerToken
 * @package OAuth2
 *
 * A security token with the property that any party in possession of
 * the token (a "bearer") can use the token in any way that any other
 * party in possession of it can.  Using a bearer token does not
 * require a bearer to prove possession of cryptographic key material
 * (proof-of-possession).
 */
interface BearerTokenInterface
{
    public function getValue(): string;
}