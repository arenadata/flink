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

import org.apache.flink.shaded.netty4.io.netty.buffer.Unpooled;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelDuplexHandler;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandlerContext;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelPromise;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.DefaultFullHttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderValues;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaders;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpVersion;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.cookie.Cookie;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import org.apache.flink.shaded.netty4.io.netty.util.AttributeKey;
import org.apache.flink.shaded.netty4.io.netty.util.ReferenceCountUtil;

import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.apache.flink.util.Preconditions.checkNotNull;

/** Netty handler that enforces SQL Gateway REST SPNEGO authentication. */
final class SqlGatewaySpnegoAuthenticationHandler extends ChannelDuplexHandler {

    static final String HADOOP_AUTH_COOKIE = "hadoop.auth";

    private static final Logger LOG =
            LoggerFactory.getLogger(SqlGatewaySpnegoAuthenticationHandler.class);
    private static final AttributeKey<ResponseAuthentication> RESPONSE_AUTHENTICATION_ATTRIBUTE =
            AttributeKey.valueOf("sql-gateway-rest-spnego-response-authentication");

    private final SpnegoAuthenticator authenticator;
    private final SqlGatewayAuthenticationTokenSigner tokenSigner;
    private final String cookiePath;
    private final boolean secureCookie;
    private final Map<String, String> responseHeaders;

    SqlGatewaySpnegoAuthenticationHandler(
            SpnegoAuthenticator authenticator,
            SqlGatewayAuthenticationTokenSigner tokenSigner,
            String cookiePath,
            boolean secureCookie,
            Map<String, String> responseHeaders) {
        this.authenticator = checkNotNull(authenticator);
        this.tokenSigner = checkNotNull(tokenSigner);
        this.cookiePath = checkNotNull(cookiePath);
        this.secureCookie = secureCookie;
        this.responseHeaders = checkNotNull(responseHeaders);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof FullHttpRequest)) {
            ctx.fireChannelRead(msg);
            return;
        }

        FullHttpRequest request = (FullHttpRequest) msg;
        Optional<AuthenticationToken> cookieToken = getAuthenticationTokenFromCookie(request);
        if (cookieToken.isPresent()) {
            ctx.fireChannelRead(msg);
            return;
        }

        try {
            SqlGatewaySpnegoAuthenticationResult result =
                    authenticator.authenticate(
                            request.headers().get(HttpHeaderNames.AUTHORIZATION));
            if (!result.isAuthenticated()) {
                sendResponse(
                        ctx, request, HttpResponseStatus.UNAUTHORIZED, result.authenticateHeader());
                return;
            }

            AuthenticationToken authenticationToken = result.authenticationToken();
            String signedToken =
                    tokenSigner.signToken(
                            authenticationToken.getUserName(), authenticationToken.getName());
            ctx.channel()
                    .attr(RESPONSE_AUTHENTICATION_ATTRIBUTE)
                    .set(new ResponseAuthentication(signedToken, result.authenticateHeader()));
            ctx.fireChannelRead(msg);
        } catch (AuthenticationException e) {
            LOG.debug("SQL Gateway REST SPNEGO authentication failed.", e);
            sendResponse(ctx, request, HttpResponseStatus.FORBIDDEN, null);
        }
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise)
            throws Exception {
        if (msg instanceof HttpResponse) {
            ResponseAuthentication responseAuthentication =
                    ctx.channel().attr(RESPONSE_AUTHENTICATION_ATTRIBUTE).getAndSet(null);
            if (responseAuthentication != null) {
                HttpHeaders headers = ((HttpResponse) msg).headers();
                headers.add(HttpHeaderNames.SET_COOKIE, createAuthCookie(responseAuthentication));
                if (responseAuthentication.authenticateHeader() != null) {
                    headers.set(
                            HttpHeaderNames.WWW_AUTHENTICATE,
                            responseAuthentication.authenticateHeader());
                }
            }
        }
        ctx.write(msg, promise);
    }

    private Optional<AuthenticationToken> getAuthenticationTokenFromCookie(
            FullHttpRequest request) {
        List<String> cookieHeaders = request.headers().getAll(HttpHeaderNames.COOKIE);
        for (String cookieHeader : cookieHeaders) {
            Set<Cookie> cookies = ServerCookieDecoder.STRICT.decode(cookieHeader);
            for (Cookie cookie : cookies) {
                if (HADOOP_AUTH_COOKIE.equals(cookie.name())) {
                    return tokenSigner.verifyToken(cookie.value());
                }
            }
        }
        return Optional.empty();
    }

    private void sendResponse(
            ChannelHandlerContext ctx,
            FullHttpRequest request,
            HttpResponseStatus status,
            @Nullable String authenticateHeader) {
        FullHttpResponse response =
                new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, Unpooled.EMPTY_BUFFER);
        responseHeaders.forEach((name, value) -> response.headers().set(name, value));
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
        if (authenticateHeader != null) {
            response.headers().set(HttpHeaderNames.WWW_AUTHENTICATE, authenticateHeader);
        }
        if (!HttpHeaderValues.CLOSE.contentEqualsIgnoreCase(
                request.headers().get(HttpHeaderNames.CONNECTION))) {
            response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        }
        ReferenceCountUtil.release(request);
        ctx.writeAndFlush(response);
    }

    private String createAuthCookie(ResponseAuthentication responseAuthentication) {
        StringBuilder cookie =
                new StringBuilder(HADOOP_AUTH_COOKIE)
                        .append("=\"")
                        .append(responseAuthentication.signedToken())
                        .append("\"")
                        .append("; Path=")
                        .append(cookiePath);
        if (secureCookie) {
            cookie.append("; Secure");
        }
        cookie.append("; HttpOnly");
        return cookie.toString();
    }

    private static final class ResponseAuthentication {
        private final String signedToken;
        @Nullable private final String authenticateHeader;

        private ResponseAuthentication(String signedToken, @Nullable String authenticateHeader) {
            this.signedToken = signedToken;
            this.authenticateHeader = authenticateHeader;
        }

        private String signedToken() {
            return signedToken;
        }

        @Nullable
        private String authenticateHeader() {
            return authenticateHeader;
        }
    }
}
