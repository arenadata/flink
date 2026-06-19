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

package org.apache.flink.runtime.webmonitor.security;

import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests for {@link JobManagerAuthenticationTokenSigner}. */
class JobManagerAuthenticationTokenSignerTest {

    private static final byte[] SECRET = "shared-secret".getBytes(StandardCharsets.UTF_8);
    private static final Clock NOW = Clock.fixed(Instant.ofEpochMilli(10_000L), ZoneOffset.UTC);

    @Test
    void shouldSignAndVerifyAuthenticationToken() {
        JobManagerAuthenticationTokenSigner signer = signer(NOW, Duration.ofHours(1));

        Optional<AuthenticationToken> token =
                signer.verifyToken(signer.signToken("alice", "alice@EXAMPLE.COM"));

        assertThat(token)
                .hasValueSatisfying(
                        authenticationToken -> {
                            assertThat(authenticationToken.getUserName()).isEqualTo("alice");
                            assertThat(authenticationToken.getName())
                                    .isEqualTo("alice@EXAMPLE.COM");
                            assertThat(authenticationToken.getType())
                                    .isEqualTo(
                                            JobManagerAuthenticationTokenSigner
                                                    .TOKEN_TYPE_KERBEROS);
                        });
    }

    @Test
    void shouldRejectInvalidSignature() {
        JobManagerAuthenticationTokenSigner signer = signer(NOW, Duration.ofHours(1));
        String signedToken = signer.signToken("alice", "alice@EXAMPLE.COM");

        assertThat(signer.verifyToken(signedToken + "tampered")).isEmpty();
    }

    @Test
    void shouldRejectExpiredToken() {
        JobManagerAuthenticationTokenSigner signer = signer(NOW, Duration.ofMillis(1));
        String signedToken = signer.signToken("alice", "alice@EXAMPLE.COM");
        JobManagerAuthenticationTokenSigner verifier =
                signer(Clock.offset(NOW, Duration.ofMillis(2)), Duration.ofMillis(1));

        assertThat(verifier.verifyToken(signedToken)).isEmpty();
    }

    @Test
    void shouldAcceptQuotedCookieValue() {
        JobManagerAuthenticationTokenSigner signer = signer(NOW, Duration.ofHours(1));
        String signedToken = signer.signToken("alice", "alice@EXAMPLE.COM");

        assertThat(signer.verifyToken("\"" + signedToken + "\"")).isPresent();
    }

    private static JobManagerAuthenticationTokenSigner signer(Clock clock, Duration tokenValidity) {
        return new JobManagerAuthenticationTokenSigner(SECRET, tokenValidity, clock);
    }
}
