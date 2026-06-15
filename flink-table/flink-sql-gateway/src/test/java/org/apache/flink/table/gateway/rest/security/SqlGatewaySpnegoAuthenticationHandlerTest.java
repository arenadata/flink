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

import org.apache.flink.shaded.netty4.io.netty.channel.embedded.EmbeddedChannel;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.DefaultFullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.DefaultFullHttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpMethod;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpVersion;

import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests for {@link SqlGatewaySpnegoAuthenticationHandler}. */
class SqlGatewaySpnegoAuthenticationHandlerTest {

    private static final byte[] SECRET = "secret".getBytes();
    private static final Clock NOW = Clock.fixed(Instant.ofEpochMilli(10_000L), ZoneOffset.UTC);

    @Test
    void shouldChallengeUnauthenticatedRequest() {
        EmbeddedChannel channel =
                channel(authorization -> SqlGatewaySpnegoAuthenticationResult.challenge("Negotiate"));

        channel.writeInbound(request());

        FullHttpResponse response = channel.readOutbound();
        try {
            assertThat(response.status()).isEqualTo(HttpResponseStatus.UNAUTHORIZED);
            assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Negotiate");
        } finally {
            response.release();
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldRejectInvalidSpnegoToken() {
        EmbeddedChannel channel =
                channel(
                        authorization -> {
                            throw new AuthenticationException("bad token");
                        });

        FullHttpRequest request = request();
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Negotiate invalid");
        channel.writeInbound(request);

        FullHttpResponse response = channel.readOutbound();
        try {
            assertThat(response.status()).isEqualTo(HttpResponseStatus.FORBIDDEN);
            assertThat(response.headers().contains(HttpHeaderNames.WWW_AUTHENTICATE)).isFalse();
        } finally {
            response.release();
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldPassThroughValidCookie() {
        SqlGatewayAuthenticationTokenSigner signer = signer(NOW);
        String signedToken = signer.signToken("alice", "alice@EXAMPLE.COM");
        EmbeddedChannel channel =
                channel(authorization -> SqlGatewaySpnegoAuthenticationResult.challenge("Negotiate"));

        FullHttpRequest request = request();
        request.headers()
                .set(
                        HttpHeaderNames.COOKIE,
                        SqlGatewaySpnegoAuthenticationHandler.HADOOP_AUTH_COOKIE
                                + "=\""
                                + signedToken
                                + "\"");
        channel.writeInbound(request);

        FullHttpRequest forwarded = channel.readInbound();
        try {
            assertThat(forwarded.uri()).isEqualTo("/v1/info");
            assertThat((Object) channel.readOutbound()).isNull();
        } finally {
            forwarded.release();
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldIgnoreExpiredCookieAndRestartChallenge() {
        String expiredToken = signer(NOW).signToken("alice", "alice@EXAMPLE.COM");
        EmbeddedChannel channel =
                new EmbeddedChannel(
                        handler(
                        authorization ->
                                SqlGatewaySpnegoAuthenticationResult.challenge("Negotiate"),
                        new SqlGatewayAuthenticationTokenSigner(
                                SECRET,
                                Duration.ofMillis(1),
                                Clock.offset(NOW, Duration.ofMillis(2)))));

        FullHttpRequest request = request();
        request.headers()
                .set(
                        HttpHeaderNames.COOKIE,
                        SqlGatewaySpnegoAuthenticationHandler.HADOOP_AUTH_COOKIE
                                + "=\""
                                + expiredToken
                                + "\"");
        channel.writeInbound(request);

        FullHttpResponse response = channel.readOutbound();
        try {
            assertThat(response.status()).isEqualTo(HttpResponseStatus.UNAUTHORIZED);
            assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Negotiate");
        } finally {
            response.release();
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldIssueCookieAfterSuccessfulSpnegoAuthentication() {
        EmbeddedChannel channel =
                channel(
                        authorization ->
                                SqlGatewaySpnegoAuthenticationResult.authenticated(
                                        new AuthenticationToken(
                                                "alice",
                                                "alice@EXAMPLE.COM",
                                                SqlGatewayAuthenticationTokenSigner
                                                        .TOKEN_TYPE_KERBEROS),
                                        "Negotiate server-token"));

        FullHttpRequest request = request();
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Negotiate client-token");
        channel.writeInbound(request);
        FullHttpRequest forwarded = channel.readInbound();
        forwarded.release();

        channel.writeOutbound(
                new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK));
        FullHttpResponse response = channel.readOutbound();
        try {
            assertThat(response.headers().get(HttpHeaderNames.SET_COOKIE))
                    .contains(SqlGatewaySpnegoAuthenticationHandler.HADOOP_AUTH_COOKIE + "=\"")
                    .contains("; Path=/")
                    .contains("; HttpOnly");
            assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Negotiate server-token");
        } finally {
            response.release();
            channel.finishAndReleaseAll();
        }
    }

    private static EmbeddedChannel channel(SpnegoAuthenticator authenticator) {
        return new EmbeddedChannel(handler(authenticator, signer(NOW)));
    }

    private static SqlGatewaySpnegoAuthenticationHandler handler(
            SpnegoAuthenticator authenticator, SqlGatewayAuthenticationTokenSigner signer) {
        return new SqlGatewaySpnegoAuthenticationHandler(
                authenticator, signer, "/", false, Collections.emptyMap());
    }

    private static SqlGatewayAuthenticationTokenSigner signer(Clock clock) {
        return new SqlGatewayAuthenticationTokenSigner(SECRET, Duration.ofMillis(1), clock);
    }

    private static FullHttpRequest request() {
        return new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/v1/info");
    }
}
