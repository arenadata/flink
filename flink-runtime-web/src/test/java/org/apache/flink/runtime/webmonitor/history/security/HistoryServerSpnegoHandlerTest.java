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

import org.apache.flink.configuration.Configuration;
import org.apache.flink.configuration.HistoryServerOptions;
import org.apache.flink.configuration.HistoryServerOptions.HistoryServerWebAuthenticationType;

import org.apache.flink.shaded.netty4.io.netty.channel.embedded.EmbeddedChannel;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.DefaultFullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpMethod;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpVersion;

import org.apache.hadoop.security.authentication.client.AuthenticatedURL;
import org.apache.hadoop.security.authentication.client.KerberosAuthenticator;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests for {@link HistoryServerWebAuthenticationHandler}. */
class HistoryServerSpnegoHandlerTest {

    private static final byte[] SECRET = "shared-secret".getBytes(StandardCharsets.UTF_8);

    @TempDir private Path tempDir;

    @Test
    void shouldNotCreateHandlerWhenAuthenticationIsDisabled() throws Exception {
        assertThat(HistoryServerWebAuthenticationHandler.createFactory(new Configuration(), false))
                .isEmpty();
    }

    @Test
    void shouldChallengeUnauthenticatedRequest() throws Exception {
        EmbeddedChannel channel = createChannel(false);
        try {
            assertThat(channel.writeInbound(getRequest())).isFalse();

            FullHttpResponse response = channel.readOutbound();
            assertThat(response.status()).isEqualTo(HttpResponseStatus.UNAUTHORIZED);
            assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo(KerberosAuthenticator.NEGOTIATE);
            assertThat(response.headers().getInt(HttpHeaderNames.CONTENT_LENGTH)).isZero();
            assertThat(response.headers().getAll(HttpHeaderNames.SET_COOKIE))
                    .anySatisfy(
                            cookie ->
                                    assertThat(cookie)
                                            .startsWith(AuthenticatedURL.AUTH_COOKIE + "=")
                                            .contains("Max-Age=0")
                                            .contains("HttpOnly"));
            response.release();
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldRejectMalformedSpnegoToken() throws Exception {
        EmbeddedChannel channel = createChannel(false);
        try {
            FullHttpRequest request = getRequest();
            request.headers()
                    .set(
                            KerberosAuthenticator.AUTHORIZATION,
                            KerberosAuthenticator.NEGOTIATE + " %%%");

            assertThat(channel.writeInbound(request)).isFalse();

            FullHttpResponse response = channel.readOutbound();
            assertThat(response.status()).isEqualTo(HttpResponseStatus.FORBIDDEN);
            assertThat(response.headers().contains(HttpHeaderNames.WWW_AUTHENTICATE)).isFalse();
            assertThat(response.headers().getAll(HttpHeaderNames.SET_COOKIE))
                    .anySatisfy(
                            cookie ->
                                    assertThat(cookie)
                                            .startsWith(AuthenticatedURL.AUTH_COOKIE + "=")
                                            .contains("Max-Age=0"));
            response.release();
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldPassThroughRequestWithValidSignedCookie() throws Exception {
        EmbeddedChannel channel = createChannel(false);
        FullHttpRequest request = getRequest();
        request.headers()
                .set(
                        HttpHeaderNames.COOKIE,
                        AuthenticatedURL.AUTH_COOKIE
                                + "=\""
                                + createSignedCookie(System.currentTimeMillis() + 60_000L)
                                + "\"");

        try {
            assertThat(channel.writeInbound(request)).isTrue();
            assertThat((Object) channel.readInbound()).isSameAs(request);
        } finally {
            request.release();
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldRestartSpnegoChallengeForExpiredCookie() throws Exception {
        EmbeddedChannel channel = createChannel(false);
        FullHttpRequest request = getRequest();
        request.headers()
                .set(
                        HttpHeaderNames.COOKIE,
                        AuthenticatedURL.AUTH_COOKIE
                                + "=\""
                                + createSignedCookie(System.currentTimeMillis() - 60_000L)
                                + "\"");

        try {
            assertThat(channel.writeInbound(request)).isFalse();

            FullHttpResponse response = channel.readOutbound();
            assertThat(response.status()).isEqualTo(HttpResponseStatus.UNAUTHORIZED);
            assertThat(response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE))
                    .isEqualTo(KerberosAuthenticator.NEGOTIATE);
            response.release();
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldMarkAuthenticationCookieSecureWhenSslIsEnabled() throws Exception {
        EmbeddedChannel channel = createChannel(true);
        try {
            assertThat(channel.writeInbound(getRequest())).isFalse();

            FullHttpResponse response = channel.readOutbound();
            assertThat(response.headers().getAll(HttpHeaderNames.SET_COOKIE))
                    .anySatisfy(cookie -> assertThat(cookie).contains("Secure"));
            response.release();
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private EmbeddedChannel createChannel(boolean secureCookie) throws Exception {
        HistoryServerWebAuthenticationHandler.Factory factory =
                HistoryServerWebAuthenticationHandler.createFactory(
                                createKerberosConfiguration(), secureCookie)
                        .orElseThrow();
        return new EmbeddedChannel(factory.createHandler());
    }

    private Configuration createKerberosConfiguration() throws Exception {
        Configuration configuration = new Configuration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_TYPE,
                HistoryServerWebAuthenticationType.KERBEROS);
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL,
                "HTTP/localhost@EXAMPLE.COM");
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_KEYTAB,
                Files.createTempFile(tempDir, "history-server", ".keytab").toString());
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET,
                new String(SECRET, StandardCharsets.UTF_8));
        return configuration;
    }

    private static FullHttpRequest getRequest() {
        return new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1, HttpMethod.GET, "/jobs/overview");
    }

    private static String createSignedCookie(long expires) {
        AuthenticationToken token =
                new AuthenticationToken(
                        "alice", "alice@EXAMPLE.COM", HistoryServerSpnegoAuthenticator.TOKEN_TYPE);
        token.setExpires(expires);
        return new HistoryServerAuthenticationTokenSigner(SECRET).sign(token);
    }
}
