/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.table.gateway.rest.security;

import org.apache.hadoop.security.authentication.server.AuthenticationToken;

import javax.annotation.Nullable;

import static org.apache.flink.util.Preconditions.checkNotNull;

/** Result of one SPNEGO acceptor step. */
final class SqlGatewaySpnegoAuthenticationResult {

    @Nullable private final AuthenticationToken authenticationToken;
    @Nullable private final String authenticateHeader;

    private SqlGatewaySpnegoAuthenticationResult(
            @Nullable AuthenticationToken authenticationToken, @Nullable String authenticateHeader) {
        this.authenticationToken = authenticationToken;
        this.authenticateHeader = authenticateHeader;
    }

    static SqlGatewaySpnegoAuthenticationResult authenticated(
            AuthenticationToken authenticationToken, @Nullable String authenticateHeader) {
        return new SqlGatewaySpnegoAuthenticationResult(authenticationToken, authenticateHeader);
    }

    static SqlGatewaySpnegoAuthenticationResult challenge(@Nullable String authenticateHeader) {
        return new SqlGatewaySpnegoAuthenticationResult(null, authenticateHeader);
    }

    boolean isAuthenticated() {
        return authenticationToken != null;
    }

    AuthenticationToken authenticationToken() {
        return checkNotNull(authenticationToken);
    }

    @Nullable
    String authenticateHeader() {
        return authenticateHeader;
    }
}
