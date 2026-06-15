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

package org.apache.flink.runtime.webmonitor.history.security;

import java.util.Optional;

/** Result of HistoryServer web authentication for a single HTTP request. */
final class HistoryServerAuthenticationResult {

    enum Status {
        AUTHENTICATED,
        UNAUTHORIZED,
        FORBIDDEN
    }

    private final Status status;
    private final Optional<String> userName;
    private final Optional<String> negotiateToken;
    private final Optional<String> signedCookie;

    private HistoryServerAuthenticationResult(
            Status status,
            Optional<String> userName,
            Optional<String> negotiateToken,
            Optional<String> signedCookie) {
        this.status = status;
        this.userName = userName;
        this.negotiateToken = negotiateToken;
        this.signedCookie = signedCookie;
    }

    static HistoryServerAuthenticationResult authenticated(String userName) {
        return new HistoryServerAuthenticationResult(
                Status.AUTHENTICATED, Optional.of(userName), Optional.empty(), Optional.empty());
    }

    static HistoryServerAuthenticationResult authenticated(String userName, String signedCookie) {
        return new HistoryServerAuthenticationResult(
                Status.AUTHENTICATED,
                Optional.of(userName),
                Optional.empty(),
                Optional.of(signedCookie));
    }

    static HistoryServerAuthenticationResult unauthorized() {
        return unauthorized(Optional.empty());
    }

    static HistoryServerAuthenticationResult unauthorized(Optional<String> negotiateToken) {
        return new HistoryServerAuthenticationResult(
                Status.UNAUTHORIZED, Optional.empty(), negotiateToken, Optional.empty());
    }

    static HistoryServerAuthenticationResult forbidden() {
        return new HistoryServerAuthenticationResult(
                Status.FORBIDDEN, Optional.empty(), Optional.empty(), Optional.empty());
    }

    Status getStatus() {
        return status;
    }

    Optional<String> getUserName() {
        return userName;
    }

    Optional<String> getNegotiateToken() {
        return negotiateToken;
    }

    Optional<String> getSignedCookie() {
        return signedCookie;
    }
}
