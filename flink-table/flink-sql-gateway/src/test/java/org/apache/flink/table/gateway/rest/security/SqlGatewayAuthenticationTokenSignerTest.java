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

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests for {@link SqlGatewayAuthenticationTokenSigner}. */
class SqlGatewayAuthenticationTokenSignerTest {

    private static final Clock NOW = Clock.fixed(Instant.ofEpochMilli(10_000L), ZoneOffset.UTC);

    @Test
    void shouldSignAndVerifyKerberosToken() {
        SqlGatewayAuthenticationTokenSigner signer =
                new SqlGatewayAuthenticationTokenSigner(
                        "secret".getBytes(), Duration.ofHours(10), NOW);

        String signedToken = signer.signToken("alice", "alice@EXAMPLE.COM");

        Optional<AuthenticationToken> token = signer.verifyToken(signedToken);
        assertThat(token).isPresent();
        assertThat(token.orElseThrow().getUserName()).isEqualTo("alice");
        assertThat(token.orElseThrow().getName()).isEqualTo("alice@EXAMPLE.COM");
        assertThat(token.orElseThrow().getType())
                .isEqualTo(SqlGatewayAuthenticationTokenSigner.TOKEN_TYPE_KERBEROS);
    }

    @Test
    void shouldRejectInvalidSignature() {
        SqlGatewayAuthenticationTokenSigner signer =
                new SqlGatewayAuthenticationTokenSigner(
                        "secret".getBytes(), Duration.ofHours(10), NOW);

        String signedToken = signer.signToken("alice", "alice@EXAMPLE.COM");

        assertThat(signer.verifyToken(signedToken.replace("alice", "bob"))).isEmpty();
    }

    @Test
    void shouldRejectExpiredToken() {
        SqlGatewayAuthenticationTokenSigner issuingSigner =
                new SqlGatewayAuthenticationTokenSigner(
                        "secret".getBytes(), Duration.ofMillis(1), NOW);
        SqlGatewayAuthenticationTokenSigner verifyingSigner =
                new SqlGatewayAuthenticationTokenSigner(
                        "secret".getBytes(),
                        Duration.ofMillis(1),
                        Clock.offset(NOW, Duration.ofMillis(2)));

        String signedToken = issuingSigner.signToken("alice", "alice@EXAMPLE.COM");

        assertThat(verifyingSigner.verifyToken(signedToken)).isEmpty();
    }
}
