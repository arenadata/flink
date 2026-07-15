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

import org.apache.flink.runtime.rest.handler.router.RouteResult;
import org.apache.flink.runtime.rest.handler.router.RoutedRequest;

import org.apache.flink.shaded.netty4.io.netty.buffer.ByteBuf;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandlerContext;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelInboundHandlerAdapter;
import org.apache.flink.shaded.netty4.io.netty.channel.embedded.EmbeddedChannel;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.DefaultFullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpMethod;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpVersion;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.LastHttpContent;
import org.apache.flink.shaded.netty4.io.netty.util.ReferenceCountUtil;

import org.apache.hadoop.security.authentication.client.AuthenticatedURL;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests for {@link JobManagerAuthenticatedUserHandler}. */
class JobManagerAuthenticatedUserHandlerTest {

    private static final Clock NOW = Clock.fixed(Instant.ofEpochMilli(10_000L), ZoneOffset.UTC);
    private static final byte[] SECRET = "secret".getBytes(StandardCharsets.UTF_8);

    @Test
    void shouldReturnUnauthenticatedResponseWhenAuthenticationIsDisabled() {
        EmbeddedChannel channel = new EmbeddedChannel(new JobManagerAuthenticatedUserHandler());
        DefaultFullHttpRequest request =
                new DefaultFullHttpRequest(
                        HttpVersion.HTTP_1_1,
                        HttpMethod.GET,
                        JobManagerAuthenticatedUserHeaders.URL);

        try {
            assertThat(channel.writeInbound(routedRequest(request))).isFalse();

            HttpResponse response = channel.readOutbound();
            assertThat(response.status()).isEqualTo(HttpResponseStatus.OK);
            assertThat(response.headers().get(HttpHeaderNames.CACHE_CONTROL)).isEqualTo("no-store");
            ByteBuf content = channel.readOutbound();
            LastHttpContent lastContent = channel.readOutbound();
            try {
                assertThat(content.toString(StandardCharsets.UTF_8))
                        .contains("\"authenticated\":false");
                assertThat(lastContent).isSameAs(LastHttpContent.EMPTY_LAST_CONTENT);
            } finally {
                ReferenceCountUtil.release(content);
                ReferenceCountUtil.release(lastContent);
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldReturnAuthenticatedUserFromCurrentRequest() {
        JobManagerAuthenticationTokenSigner signer =
                new JobManagerAuthenticationTokenSigner(SECRET, Duration.ofHours(1), NOW);
        JobManagerAuthenticatedUserHandler authenticatedUserHandler =
                new JobManagerAuthenticatedUserHandler();
        EmbeddedChannel channel =
                new EmbeddedChannel(
                        new JobManagerWebAuthenticationHandler(
                                authorization ->
                                        JobManagerSpnegoAuthenticationResult.challenge("Negotiate"),
                                signer,
                                "/",
                                false,
                                Collections.emptyMap()),
                        new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelRead(ChannelHandlerContext ctx, Object msg)
                                    throws Exception {
                                if (msg instanceof FullHttpRequest) {
                                    authenticatedUserHandler.channelRead(
                                            ctx, routedRequest((FullHttpRequest) msg));
                                } else {
                                    super.channelRead(ctx, msg);
                                }
                            }
                        });
        DefaultFullHttpRequest request =
                new DefaultFullHttpRequest(
                        HttpVersion.HTTP_1_1,
                        HttpMethod.GET,
                        JobManagerAuthenticatedUserHeaders.URL);
        request.headers()
                .set(
                        HttpHeaderNames.COOKIE,
                        AuthenticatedURL.AUTH_COOKIE
                                + "=\""
                                + signer.signToken("alice", "alice@EXAMPLE.COM")
                                + "\"");

        try {
            assertThat(channel.writeInbound(request)).isFalse();

            HttpResponse response = channel.readOutbound();
            assertThat(response.status()).isEqualTo(HttpResponseStatus.OK);
            ByteBuf content = channel.readOutbound();
            LastHttpContent lastContent = channel.readOutbound();
            try {
                assertThat(content.toString(StandardCharsets.UTF_8))
                        .contains("\"authenticated\":true")
                        .contains("\"user\":\"alice\"")
                        .contains("\"principal\":\"alice@EXAMPLE.COM\"")
                        .contains(
                                "\"type\":\""
                                        + JobManagerAuthenticationTokenSigner.TOKEN_TYPE_KERBEROS
                                        + "\"");
                assertThat(lastContent).isSameAs(LastHttpContent.EMPTY_LAST_CONTENT);
            } finally {
                ReferenceCountUtil.release(content);
                ReferenceCountUtil.release(lastContent);
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static RoutedRequest<Object> routedRequest(FullHttpRequest request) {
        return new RoutedRequest<>(
                new RouteResult<>(
                        request.uri(),
                        request.uri(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        new JobManagerAuthenticatedUserHandler()),
                request);
    }
}
