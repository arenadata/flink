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
import org.apache.flink.shaded.netty4.io.netty.buffer.Unpooled;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelDuplexHandler;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelFutureListener;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandler;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandlerContext;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelPromise;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.DefaultFullHttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderValues;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpUtil;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpVersion;
import org.apache.flink.shaded.netty4.io.netty.util.AttributeKey;
import org.apache.flink.shaded.netty4.io.netty.util.ReferenceCountUtil;
import org.apache.flink.util.ConfigurationException;

import org.apache.hadoop.security.authentication.client.KerberosAuthenticator;

import java.util.ArrayDeque;
import java.util.Optional;
import java.util.Queue;

/** Netty handler that enforces HistoryServer web authentication when configured. */
public final class HistoryServerWebAuthenticationHandler extends ChannelDuplexHandler {

    private static final AttributeKey<Queue<String>> PENDING_AUTH_COOKIES =
            AttributeKey.valueOf("history-server-pending-auth-cookies");

    private final HistoryServerSpnegoAuthenticator authenticator;
    private final boolean secureCookie;

    private HistoryServerWebAuthenticationHandler(
            HistoryServerSpnegoAuthenticator authenticator, boolean secureCookie) {
        this.authenticator = authenticator;
        this.secureCookie = secureCookie;
    }

    public static Optional<Factory> createFactory(Configuration configuration, boolean secureCookie)
            throws ConfigurationException {
        return HistoryServerSpnegoAuthenticator.fromConfiguration(configuration)
                .map(authenticator -> () -> new HistoryServerWebAuthenticationHandler(authenticator, secureCookie));
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (!(msg instanceof FullHttpRequest)) {
            ctx.fireChannelRead(msg);
            return;
        }

        FullHttpRequest request = (FullHttpRequest) msg;
        HistoryServerAuthenticationResult authenticationResult =
                authenticator.authenticate(request);

        switch (authenticationResult.getStatus()) {
            case AUTHENTICATED:
                authenticationResult
                        .getSignedCookie()
                        .map(cookie -> authenticator.createAuthenticationCookie(cookie, secureCookie))
                        .ifPresent(cookie -> enqueuePendingCookie(ctx, cookie));
                ctx.fireChannelRead(msg);
                break;
            case UNAUTHORIZED:
                writeResponse(
                        ctx,
                        request,
                        createUnauthorizedResponse(authenticationResult.getNegotiateToken()));
                break;
            case FORBIDDEN:
                writeResponse(ctx, request, createForbiddenResponse());
                break;
            default:
                throw new IllegalStateException(
                        "Unknown authentication status: " + authenticationResult.getStatus());
        }
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise)
            throws Exception {
        if (msg instanceof HttpResponse) {
            Queue<String> pendingCookies = ctx.channel().attr(PENDING_AUTH_COOKIES).get();
            if (pendingCookies != null) {
                String cookie = pendingCookies.poll();
                if (cookie != null) {
                    ((HttpResponse) msg).headers().add(HttpHeaderNames.SET_COOKIE, cookie);
                }
            }
        }
        super.write(ctx, msg, promise);
    }

    private void enqueuePendingCookie(ChannelHandlerContext ctx, String cookie) {
        Queue<String> pendingCookies = ctx.channel().attr(PENDING_AUTH_COOKIES).get();
        if (pendingCookies == null) {
            pendingCookies = new ArrayDeque<>();
            ctx.channel().attr(PENDING_AUTH_COOKIES).set(pendingCookies);
        }
        pendingCookies.add(cookie);
    }

    private FullHttpResponse createUnauthorizedResponse(Optional<String> negotiateToken) {
        FullHttpResponse response =
                new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1,
                        HttpResponseStatus.UNAUTHORIZED,
                        Unpooled.EMPTY_BUFFER);
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
        response.headers().set(HttpHeaderNames.WWW_AUTHENTICATE, negotiateValue(negotiateToken));
        response.headers()
                .add(
                        HttpHeaderNames.SET_COOKIE,
                        authenticator.createExpiredAuthenticationCookie(secureCookie));
        return response;
    }

    private FullHttpResponse createForbiddenResponse() {
        FullHttpResponse response =
                new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1,
                        HttpResponseStatus.FORBIDDEN,
                        Unpooled.EMPTY_BUFFER);
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
        response.headers()
                .add(
                        HttpHeaderNames.SET_COOKIE,
                        authenticator.createExpiredAuthenticationCookie(secureCookie));
        return response;
    }

    private static String negotiateValue(Optional<String> negotiateToken) {
        return negotiateToken
                .map(token -> KerberosAuthenticator.NEGOTIATE + " " + token)
                .orElse(KerberosAuthenticator.NEGOTIATE);
    }

    private static void writeResponse(
            ChannelHandlerContext ctx, FullHttpRequest request, FullHttpResponse response) {
        boolean keepAlive = HttpUtil.isKeepAlive(request);
        ReferenceCountUtil.release(request);
        if (keepAlive) {
            response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
            ctx.writeAndFlush(response);
        } else {
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }
    }

    /** Factory for per-channel HistoryServer authentication handlers. */
    public interface Factory {
        ChannelHandler createHandler();
    }
}
