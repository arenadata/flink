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
import org.apache.flink.util.ConfigurationException;

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
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaders;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpMethod;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponse;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponseStatus;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpUtil;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpVersion;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.LastHttpContent;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.cookie.Cookie;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.multipart.HttpPostRequestDecoder;
import org.apache.flink.shaded.netty4.io.netty.util.AttributeKey;
import org.apache.flink.shaded.netty4.io.netty.util.ReferenceCountUtil;

import org.apache.hadoop.security.authentication.client.AuthenticatedURL;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.apache.flink.util.Preconditions.checkNotNull;

/** Netty handler that enforces JobManager web SPNEGO authentication. */
public final class JobManagerWebAuthenticationHandler extends ChannelDuplexHandler {

    private static final Logger LOG =
            LoggerFactory.getLogger(JobManagerWebAuthenticationHandler.class);

    private static final AttributeKey<ResponseAuthentication> RESPONSE_AUTHENTICATION_ATTRIBUTE =
            AttributeKey.valueOf("jobmanager-web-spnego-response-authentication");
    private static final AttributeKey<JobManagerAuthenticatedUser> AUTHENTICATED_USER =
            AttributeKey.valueOf("jobmanager-web-authenticated-user");
    private static final AttributeKey<AuthenticationToken> PRE_AUTHENTICATED_TOKEN =
            AttributeKey.valueOf("jobmanager-web-pre-authenticated-token");

    private final SpnegoAuthenticator authenticator;
    private final JobManagerAuthenticationTokenSigner tokenSigner;
    private final String cookiePath;
    private final boolean secureCookie;
    private final Map<String, String> responseHeaders;

    JobManagerWebAuthenticationHandler(
            SpnegoAuthenticator authenticator,
            JobManagerAuthenticationTokenSigner tokenSigner,
            String cookiePath,
            boolean secureCookie,
            Map<String, String> responseHeaders) {
        this.authenticator = checkNotNull(authenticator);
        this.tokenSigner = checkNotNull(tokenSigner);
        this.cookiePath = checkNotNull(cookiePath);
        this.secureCookie = secureCookie;
        this.responseHeaders = checkNotNull(responseHeaders);
    }

    static ChannelHandler createPreFileUploadHandler(
            SpnegoAuthenticator authenticator,
            JobManagerAuthenticationTokenSigner tokenSigner,
            String cookiePath,
            boolean secureCookie,
            Map<String, String> responseHeaders) {
        return new PreFileUploadAuthenticationHandler(
                authenticator, tokenSigner, cookiePath, secureCookie, responseHeaders);
    }

    public static Optional<Factory> createFactory(
            Configuration configuration, Map<String, String> responseHeaders)
            throws ConfigurationException {
        Optional<JobManagerWebAuthenticationConfig> config =
                JobManagerWebAuthenticationConfig.fromConfiguration(configuration);
        if (!config.isPresent()) {
            return Optional.empty();
        }

        JobManagerWebAuthenticationConfig authenticationConfig = config.get();
        SpnegoAuthenticator authenticator =
                JobManagerSpnegoAuthenticator.create(authenticationConfig);
        JobManagerAuthenticationTokenSigner signer =
                new JobManagerAuthenticationTokenSigner(
                        authenticationConfig.getSignatureSecret(),
                        authenticationConfig.getTokenValidity(),
                        Clock.systemUTC());

        return Optional.of(
                new Factory() {
                    @Override
                    public ChannelHandler createHandler() {
                        return new JobManagerWebAuthenticationHandler(
                                authenticator,
                                signer,
                                authenticationConfig.getCookiePath(),
                                authenticationConfig.isSecureCookie(),
                                responseHeaders);
                    }

                    @Override
                    public ChannelHandler createPreFileUploadHandler() {
                        return JobManagerWebAuthenticationHandler.createPreFileUploadHandler(
                                authenticator,
                                signer,
                                authenticationConfig.getCookiePath(),
                                authenticationConfig.isSecureCookie(),
                                responseHeaders);
                    }
                });
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof FullHttpRequest)) {
            ctx.fireChannelRead(msg);
            return;
        }

        FullHttpRequest request = (FullHttpRequest) msg;
        AuthenticationToken preAuthenticatedToken =
                ctx.channel().attr(PRE_AUTHENTICATED_TOKEN).getAndSet(null);
        if (preAuthenticatedToken != null) {
            setAuthenticatedUser(ctx, preAuthenticatedToken);
            try {
                ctx.fireChannelRead(msg);
            } finally {
                clearAuthenticatedUser(ctx);
            }
            return;
        }

        Optional<AuthenticationToken> cookieToken =
                getAuthenticationTokenFromCookie(request, tokenSigner);
        if (cookieToken.isPresent()) {
            setAuthenticatedUser(ctx, cookieToken.get());
            try {
                ctx.fireChannelRead(msg);
            } finally {
                clearAuthenticatedUser(ctx);
            }
            return;
        }

        try {
            JobManagerSpnegoAuthenticationResult result =
                    authenticator.authenticate(
                            request.headers().get(HttpHeaderNames.AUTHORIZATION));
            if (!result.isAuthenticated()) {
                sendResponse(
                        ctx,
                        request,
                        HttpResponseStatus.UNAUTHORIZED,
                        result.authenticateHeader(),
                        true);
                return;
            }

            AuthenticationToken authenticationToken = result.authenticationToken();
            String signedToken =
                    tokenSigner.signToken(
                            authenticationToken.getUserName(), authenticationToken.getName());
            ctx.channel()
                    .attr(RESPONSE_AUTHENTICATION_ATTRIBUTE)
                    .set(new ResponseAuthentication(signedToken, result.authenticateHeader()));
            setAuthenticatedUser(ctx, authenticationToken);
            try {
                ctx.fireChannelRead(msg);
            } finally {
                clearAuthenticatedUser(ctx);
            }
        } catch (AuthenticationException e) {
            LOG.debug("JobManager web SPNEGO authentication failed.", e);
            clearAuthenticatedUser(ctx);
            sendResponse(ctx, request, HttpResponseStatus.FORBIDDEN, null, true);
        }
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise)
            throws Exception {
        if (msg instanceof HttpResponse) {
            addResponseAuthentication(
                    ctx, ((HttpResponse) msg).headers(), cookiePath, secureCookie);
        }
        ctx.write(msg, promise);
    }

    private static Optional<AuthenticationToken> getAuthenticationTokenFromCookie(
            HttpRequest request, JobManagerAuthenticationTokenSigner tokenSigner) {
        for (String cookieHeader : request.headers().getAll(HttpHeaderNames.COOKIE)) {
            try {
                Set<Cookie> cookies = ServerCookieDecoder.STRICT.decode(cookieHeader);
                for (Cookie cookie : cookies) {
                    if (AuthenticatedURL.AUTH_COOKIE.equals(cookie.name())) {
                        Optional<AuthenticationToken> token =
                                tokenSigner.verifyToken(cookie.value());
                        if (token.isPresent()) {
                            return token;
                        }
                    }
                }
            } catch (IllegalArgumentException e) {
                LOG.debug("Ignoring malformed JobManager web Cookie header.", e);
            }
        }
        return Optional.empty();
    }

    private static void setAuthenticatedUser(
            ChannelHandlerContext ctx, AuthenticationToken authenticationToken) {
        ctx.channel()
                .attr(AUTHENTICATED_USER)
                .set(
                        new JobManagerAuthenticatedUser(
                                authenticationToken.getUserName(),
                                authenticationToken.getName(),
                                authenticationToken.getType()));
    }

    private static void clearAuthenticatedUser(ChannelHandlerContext ctx) {
        ctx.channel().attr(AUTHENTICATED_USER).set(null);
    }

    public static Optional<JobManagerAuthenticatedUser> getAuthenticatedUser(
            ChannelHandlerContext ctx) {
        return Optional.ofNullable(ctx.channel().attr(AUTHENTICATED_USER).get());
    }

    private void sendResponse(
            ChannelHandlerContext ctx,
            HttpRequest request,
            HttpResponseStatus status,
            @Nullable String authenticateHeader,
            boolean expireCookie) {
        sendResponse(
                ctx,
                request,
                status,
                authenticateHeader,
                expireCookie,
                responseHeaders,
                cookiePath,
                secureCookie);
    }

    private static void sendResponse(
            ChannelHandlerContext ctx,
            HttpRequest request,
            HttpResponseStatus status,
            @Nullable String authenticateHeader,
            boolean expireCookie,
            Map<String, String> responseHeaders,
            String cookiePath,
            boolean secureCookie) {
        clearAuthenticatedUser(ctx);
        FullHttpResponse response =
                new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, Unpooled.EMPTY_BUFFER);
        responseHeaders.forEach((name, value) -> response.headers().set(name, value));
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
        if (authenticateHeader != null) {
            response.headers().set(HttpHeaderNames.WWW_AUTHENTICATE, authenticateHeader);
        }
        if (expireCookie) {
            response.headers()
                    .add(
                            HttpHeaderNames.SET_COOKIE,
                            createExpiredAuthCookie(cookiePath, secureCookie));
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);
        ReferenceCountUtil.release(request);
        if (keepAlive) {
            response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
            ctx.writeAndFlush(response);
        } else {
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }
    }

    private static void addResponseAuthentication(
            ChannelHandlerContext ctx,
            HttpHeaders headers,
            String cookiePath,
            boolean secureCookie) {
        ResponseAuthentication responseAuthentication =
                ctx.channel().attr(RESPONSE_AUTHENTICATION_ATTRIBUTE).getAndSet(null);
        if (responseAuthentication != null) {
            headers.add(
                    HttpHeaderNames.SET_COOKIE,
                    createAuthCookie(responseAuthentication, cookiePath, secureCookie));
            if (responseAuthentication.authenticateHeader() != null) {
                headers.set(
                        HttpHeaderNames.WWW_AUTHENTICATE,
                        responseAuthentication.authenticateHeader());
            }
        }
    }

    private static String createAuthCookie(
            ResponseAuthentication responseAuthentication,
            String cookiePath,
            boolean secureCookie) {
        StringBuilder cookie =
                new StringBuilder(AuthenticatedURL.AUTH_COOKIE)
                        .append("=\"")
                        .append(responseAuthentication.signedToken())
                        .append("\"; Path=")
                        .append(cookiePath);
        if (secureCookie) {
            cookie.append("; Secure");
        }
        cookie.append("; HttpOnly");
        return cookie.toString();
    }

    private static String createExpiredAuthCookie(String cookiePath, boolean secureCookie) {
        StringBuilder cookie =
                new StringBuilder(AuthenticatedURL.AUTH_COOKIE)
                        .append("=; Path=")
                        .append(cookiePath)
                        .append("; Max-Age=0");
        if (secureCookie) {
            cookie.append("; Secure");
        }
        cookie.append("; HttpOnly");
        return cookie.toString();
    }

    private static final class PreFileUploadAuthenticationHandler extends ChannelDuplexHandler {

        private final SpnegoAuthenticator authenticator;
        private final JobManagerAuthenticationTokenSigner tokenSigner;
        private final String cookiePath;
        private final boolean secureCookie;
        private final Map<String, String> responseHeaders;

        private boolean discardingRejectedRequest;

        private PreFileUploadAuthenticationHandler(
                SpnegoAuthenticator authenticator,
                JobManagerAuthenticationTokenSigner tokenSigner,
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
            if (discardingRejectedRequest) {
                if (msg instanceof LastHttpContent) {
                    discardingRejectedRequest = false;
                }
                ReferenceCountUtil.release(msg);
                return;
            }

            if (!(msg instanceof HttpRequest) || !requiresEarlyAuthentication((HttpRequest) msg)) {
                ctx.fireChannelRead(msg);
                return;
            }

            HttpRequest request = (HttpRequest) msg;
            Optional<AuthenticationToken> cookieToken =
                    getAuthenticationTokenFromCookie(request, tokenSigner);
            if (cookieToken.isPresent()) {
                ctx.channel().attr(PRE_AUTHENTICATED_TOKEN).set(cookieToken.get());
                ctx.fireChannelRead(msg);
                return;
            }

            try {
                JobManagerSpnegoAuthenticationResult result =
                        authenticator.authenticate(
                                request.headers().get(HttpHeaderNames.AUTHORIZATION));
                if (!result.isAuthenticated()) {
                    rejectRequest(
                            ctx,
                            request,
                            HttpResponseStatus.UNAUTHORIZED,
                            result.authenticateHeader());
                    return;
                }

                AuthenticationToken authenticationToken = result.authenticationToken();
                String signedToken =
                        tokenSigner.signToken(
                                authenticationToken.getUserName(), authenticationToken.getName());
                ctx.channel().attr(PRE_AUTHENTICATED_TOKEN).set(authenticationToken);
                ctx.channel()
                        .attr(RESPONSE_AUTHENTICATION_ATTRIBUTE)
                        .set(new ResponseAuthentication(signedToken, result.authenticateHeader()));
                ctx.fireChannelRead(msg);
            } catch (AuthenticationException e) {
                LOG.debug("JobManager web SPNEGO upload authentication failed.", e);
                rejectRequest(ctx, request, HttpResponseStatus.FORBIDDEN, null);
            }
        }

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise)
                throws Exception {
            if (msg instanceof HttpResponse) {
                addResponseAuthentication(
                        ctx, ((HttpResponse) msg).headers(), cookiePath, secureCookie);
                ctx.channel().attr(PRE_AUTHENTICATED_TOKEN).set(null);
            }
            ctx.write(msg, promise);
        }

        private void rejectRequest(
                ChannelHandlerContext ctx,
                HttpRequest request,
                HttpResponseStatus status,
                @Nullable String authenticateHeader) {
            clearAuthenticatedUser(ctx);
            ctx.channel().attr(PRE_AUTHENTICATED_TOKEN).set(null);
            ctx.channel().attr(RESPONSE_AUTHENTICATION_ATTRIBUTE).set(null);
            discardingRejectedRequest = !(request instanceof LastHttpContent);
            sendResponse(
                    ctx,
                    request,
                    status,
                    authenticateHeader,
                    true,
                    responseHeaders,
                    cookiePath,
                    secureCookie);
        }

        private static boolean requiresEarlyAuthentication(HttpRequest request) {
            return HttpMethod.POST.equals(request.method())
                    && HttpPostRequestDecoder.isMultipart(request);
        }
    }

    /** Factory for per-channel JobManager web authentication handlers. */
    public interface Factory {
        ChannelHandler createHandler();

        ChannelHandler createPreFileUploadHandler();
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
