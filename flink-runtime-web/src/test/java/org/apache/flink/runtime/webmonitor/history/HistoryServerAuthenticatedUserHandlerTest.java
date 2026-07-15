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

package org.apache.flink.runtime.webmonitor.history;

import org.apache.flink.runtime.rest.handler.router.RouteResult;
import org.apache.flink.runtime.rest.handler.router.RoutedRequest;

import org.apache.flink.shaded.netty4.io.netty.buffer.ByteBuf;
import org.apache.flink.shaded.netty4.io.netty.channel.embedded.EmbeddedChannel;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.DefaultFullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpMethod;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpVersion;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.LastHttpContent;
import org.apache.flink.shaded.netty4.io.netty.util.ReferenceCountUtil;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests for {@link HistoryServerAuthenticatedUserHandler}. */
class HistoryServerAuthenticatedUserHandlerTest {

    @Test
    void shouldReturnUnauthenticatedResponseWhenAuthenticationIsDisabled() {
        EmbeddedChannel channel = new EmbeddedChannel(new HistoryServerAuthenticatedUserHandler());
        DefaultFullHttpRequest request =
                new DefaultFullHttpRequest(
                        HttpVersion.HTTP_1_1,
                        HttpMethod.GET,
                        HistoryServerAuthenticatedUserHandler.URL);

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

    private static RoutedRequest<Object> routedRequest(DefaultFullHttpRequest request) {
        return new RoutedRequest<>(
                new RouteResult<>(
                        request.uri(),
                        request.uri(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        new HistoryServerAuthenticatedUserHandler()),
                request);
    }
}
