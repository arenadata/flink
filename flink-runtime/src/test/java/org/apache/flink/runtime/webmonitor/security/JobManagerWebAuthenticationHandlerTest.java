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

import org.apache.flink.configuration.Configuration;

import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandler;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandlerContext;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelInboundHandlerAdapter;
import org.apache.flink.shaded.netty4.io.netty.channel.embedded.EmbeddedChannel;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.DefaultFullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.DefaultFullHttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpMethod;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpVersion;
import org.apache.flink.shaded.netty4.io.netty.util.ReferenceCountUtil;

import org.apache.hadoop.security.authentication.client.AuthenticatedURL;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests for {@link JobManagerWebAuthenticationHandler}. */
class JobManagerWebAuthenticationHandlerTest {

    private static final byte[] SECRET = "secret".getBytes(StandardCharsets.UTF_8);
    private static final Clock NOW = Clock.fixed(Instant.ofEpochMilli(10_000L), ZoneOffset.UTC);

    @Test
    void shouldNotCreateHandlerWhenAuthenticationIsDisabled() throws Exception {
        assertThat(
                        JobManagerWebAuthenticationHandler.createFactory(
                                new Configuration(), Collections.emptyMap()))
                .isEmpty();
    }

    @Test
    void shouldChallengeUnauthenticatedRequest() {
        EmbeddedChannel channel =
                channel(
                        authorization ->
                                JobManagerSpnegoAuthenticationResult.challenge("Negotiate"));

        channel.writeInbound(request());

        FullHttpResponse response = channel.readOutbound();
        try {
            assertThat(response.status()).isEqualTo(HttpResponseStatus.UNAUTHORIZED);
            assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Negotiate");
            assertThat(response.headers().getInt(HttpHeaderNames.CONTENT_LENGTH)).isZero();
            assertThat(response.headers().getAll(HttpHeaderNames.SET_COOKIE))
                    .anySatisfy(
                            cookie ->
                                    assertThat(cookie)
                                            .startsWith(AuthenticatedURL.AUTH_COOKIE + "=")
                                            .contains("Max-Age=0")
                                            .contains("HttpOnly"));
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
            assertThat(response.headers().getAll(HttpHeaderNames.SET_COOKIE))
                    .anySatisfy(
                            cookie ->
                                    assertThat(cookie)
                                            .startsWith(AuthenticatedURL.AUTH_COOKIE + "=")
                                            .contains("Max-Age=0"));
        } finally {
            response.release();
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldPassThroughValidCookie() {
        JobManagerAuthenticationTokenSigner signer = signer(NOW, Duration.ofHours(1));
        EmbeddedChannel channel =
                channel(
                        authorization ->
                                JobManagerSpnegoAuthenticationResult.challenge("Negotiate"),
                        signer,
                        false,
                        Collections.emptyMap());

        FullHttpRequest request = request();
        request.headers()
                .set(
                        HttpHeaderNames.COOKIE,
                        AuthenticatedURL.AUTH_COOKIE
                                + "=\""
                                + signer.signToken("alice", "alice@EXAMPLE.COM")
                                + "\"");
        channel.writeInbound(request);

        FullHttpRequest forwarded = channel.readInbound();
        try {
            assertThat(forwarded.uri()).isEqualTo("/jobs/overview");
            assertThat((Object) channel.readOutbound()).isNull();
        } finally {
            forwarded.release();
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldExposeAuthenticatedUserWhileHandlingRequestWithValidSignedCookie() {
        AtomicReference<Optional<JobManagerAuthenticatedUser>> authenticatedUser =
                new AtomicReference<>(Optional.empty());
        JobManagerAuthenticationTokenSigner signer = signer(NOW, Duration.ofHours(1));
        EmbeddedChannel channel =
                channel(
                        authorization ->
                                JobManagerSpnegoAuthenticationResult.challenge("Negotiate"),
                        signer,
                        false,
                        Collections.emptyMap(),
                        new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelRead(ChannelHandlerContext ctx, Object msg) {
                                authenticatedUser.set(
                                        JobManagerWebAuthenticationHandler.getAuthenticatedUser(
                                                ctx));
                                ReferenceCountUtil.release(msg);
                            }
                        });

        FullHttpRequest request = request();
        request.headers()
                .set(
                        HttpHeaderNames.COOKIE,
                        AuthenticatedURL.AUTH_COOKIE
                                + "=\""
                                + signer.signToken("alice", "alice@EXAMPLE.COM")
                                + "\"");
        channel.writeInbound(request);

        try {
            assertThat(authenticatedUser.get())
                    .hasValueSatisfying(
                            user -> {
                                assertThat(user.getUserName()).isEqualTo("alice");
                                assertThat(user.getPrincipal()).isEqualTo("alice@EXAMPLE.COM");
                                assertThat(user.getType())
                                        .isEqualTo(
                                                JobManagerAuthenticationTokenSigner
                                                        .TOKEN_TYPE_KERBEROS);
                            });
            assertThat(
                            JobManagerWebAuthenticationHandler.getAuthenticatedUser(
                                    channel.pipeline().firstContext()))
                    .isEmpty();
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldIgnoreExpiredCookieAndRestartChallenge() {
        JobManagerAuthenticationTokenSigner signer = signer(NOW, Duration.ofMillis(1));
        String expiredToken = signer.signToken("alice", "alice@EXAMPLE.COM");
        EmbeddedChannel channel =
                channel(
                        authorization ->
                                JobManagerSpnegoAuthenticationResult.challenge("Negotiate"),
                        signer(Clock.offset(NOW, Duration.ofMillis(2)), Duration.ofMillis(1)),
                        false,
                        Collections.emptyMap());

        FullHttpRequest request = request();
        request.headers()
                .set(
                        HttpHeaderNames.COOKIE,
                        AuthenticatedURL.AUTH_COOKIE + "=\"" + expiredToken + "\"");
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
        AtomicReference<Optional<JobManagerAuthenticatedUser>> authenticatedUser =
                new AtomicReference<>(Optional.empty());
        EmbeddedChannel channel =
                channel(
                        authorization ->
                                JobManagerSpnegoAuthenticationResult.authenticated(
                                        new AuthenticationToken(
                                                "alice",
                                                "alice@EXAMPLE.COM",
                                                JobManagerAuthenticationTokenSigner
                                                        .TOKEN_TYPE_KERBEROS),
                                        "Negotiate server-token"),
                        signer(NOW, Duration.ofHours(1)),
                        false,
                        Collections.emptyMap(),
                        new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelRead(ChannelHandlerContext ctx, Object msg) {
                                authenticatedUser.set(
                                        JobManagerWebAuthenticationHandler.getAuthenticatedUser(
                                                ctx));
                                ReferenceCountUtil.release(msg);
                            }
                        });

        FullHttpRequest request = request();
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Negotiate client-token");
        channel.writeInbound(request);

        channel.writeOutbound(
                new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK));
        FullHttpResponse response = channel.readOutbound();
        try {
            assertThat(authenticatedUser.get())
                    .hasValueSatisfying(
                            user -> {
                                assertThat(user.getUserName()).isEqualTo("alice");
                                assertThat(user.getPrincipal()).isEqualTo("alice@EXAMPLE.COM");
                                assertThat(user.getType())
                                        .isEqualTo(
                                                JobManagerAuthenticationTokenSigner
                                                        .TOKEN_TYPE_KERBEROS);
                            });
            assertThat(response.headers().get(HttpHeaderNames.SET_COOKIE))
                    .contains(AuthenticatedURL.AUTH_COOKIE + "=\"")
                    .contains("; Path=/")
                    .contains("; HttpOnly");
            assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo("Negotiate server-token");
        } finally {
            response.release();
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldMarkAuthenticationCookieSecureWhenSslIsEnabled() {
        EmbeddedChannel channel =
                channel(
                        authorization ->
                                JobManagerSpnegoAuthenticationResult.authenticated(
                                        new AuthenticationToken(
                                                "alice",
                                                "alice@EXAMPLE.COM",
                                                JobManagerAuthenticationTokenSigner
                                                        .TOKEN_TYPE_KERBEROS),
                                        null),
                        signer(NOW, Duration.ofHours(1)),
                        true,
                        Collections.emptyMap());

        FullHttpRequest request = request();
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Negotiate client-token");
        channel.writeInbound(request);
        FullHttpRequest forwarded = channel.readInbound();
        forwarded.release();

        channel.writeOutbound(
                new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK));
        FullHttpResponse response = channel.readOutbound();
        try {
            assertThat(response.headers().get(HttpHeaderNames.SET_COOKIE)).contains("; Secure");
        } finally {
            response.release();
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldIncludeConfiguredResponseHeadersInChallenge() {
        EmbeddedChannel channel =
                channel(
                        authorization ->
                                JobManagerSpnegoAuthenticationResult.challenge("Negotiate"),
                        signer(NOW, Duration.ofHours(1)),
                        false,
                        Collections.singletonMap("Access-Control-Allow-Origin", "example.com"));

        channel.writeInbound(request());

        FullHttpResponse response = channel.readOutbound();
        try {
            assertThat(response.headers().get("Access-Control-Allow-Origin"))
                    .isEqualTo("example.com");
        } finally {
            response.release();
            channel.finishAndReleaseAll();
        }
    }

    private static EmbeddedChannel channel(SpnegoAuthenticator authenticator) {
        return channel(
                authenticator, signer(NOW, Duration.ofHours(1)), false, Collections.emptyMap());
    }

    private static EmbeddedChannel channel(
            SpnegoAuthenticator authenticator,
            JobManagerAuthenticationTokenSigner signer,
            boolean secureCookie,
            Map<String, String> responseHeaders,
            ChannelHandler... additionalHandlers) {
        ChannelHandler[] handlers = new ChannelHandler[additionalHandlers.length + 1];
        handlers[0] =
                new JobManagerWebAuthenticationHandler(
                        authenticator, signer, "/", secureCookie, responseHeaders);
        System.arraycopy(additionalHandlers, 0, handlers, 1, additionalHandlers.length);
        return new EmbeddedChannel(handlers);
    }

    private static JobManagerAuthenticationTokenSigner signer(Clock clock, Duration tokenValidity) {
        return new JobManagerAuthenticationTokenSigner(SECRET, tokenValidity, clock);
    }

    private static FullHttpRequest request() {
        return new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/jobs/overview");
    }
}
