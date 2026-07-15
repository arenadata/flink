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

import org.apache.flink.runtime.rest.handler.router.RoutedRequest;
import org.apache.flink.runtime.rest.handler.util.HandlerUtils;
import org.apache.flink.runtime.rest.messages.ResponseBody;
import org.apache.flink.runtime.webmonitor.history.security.HistoryServerAuthenticatedUser;
import org.apache.flink.runtime.webmonitor.history.security.HistoryServerWebAuthenticationHandler;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.annotation.JsonCreator;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandler;
import org.apache.flink.shaded.netty4.io.netty.channel.ChannelHandlerContext;
import org.apache.flink.shaded.netty4.io.netty.channel.SimpleChannelInboundHandler;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpResponseStatus;

import javax.annotation.Nullable;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/** Handler for exposing the current HistoryServer web user to the dashboard. */
@ChannelHandler.Sharable
public final class HistoryServerAuthenticatedUserHandler
        extends SimpleChannelInboundHandler<RoutedRequest<Object>> {

    public static final String URL = "/auth/user";

    private static final Map<String, String> NO_STORE_HEADERS = createNoStoreHeaders();

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, RoutedRequest<Object> routedRequest) {
        HistoryServerAuthenticatedUserResponseBody response =
                HistoryServerWebAuthenticationHandler.getAuthenticatedUser(ctx)
                        .map(HistoryServerAuthenticatedUserResponseBody::authenticated)
                        .orElseGet(HistoryServerAuthenticatedUserResponseBody::unauthenticated);

        HandlerUtils.sendResponse(
                ctx, routedRequest.getRequest(), response, HttpResponseStatus.OK, NO_STORE_HEADERS);
    }

    private static Map<String, String> createNoStoreHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaderNames.CACHE_CONTROL.toString(), "no-store");
        headers.put(HttpHeaderNames.PRAGMA.toString(), "no-cache");
        return Collections.unmodifiableMap(headers);
    }

    /** Response body for the current authenticated HistoryServer web user. */
    public static final class HistoryServerAuthenticatedUserResponseBody implements ResponseBody {

        public static final String FIELD_NAME_AUTHENTICATED = "authenticated";
        public static final String FIELD_NAME_USER = "user";
        public static final String FIELD_NAME_PRINCIPAL = "principal";
        public static final String FIELD_NAME_TYPE = "type";

        @JsonProperty(FIELD_NAME_AUTHENTICATED)
        private final boolean authenticated;

        @JsonProperty(FIELD_NAME_USER)
        @Nullable
        private final String user;

        @JsonProperty(FIELD_NAME_PRINCIPAL)
        @Nullable
        private final String principal;

        @JsonProperty(FIELD_NAME_TYPE)
        @Nullable
        private final String type;

        @JsonCreator
        public HistoryServerAuthenticatedUserResponseBody(
                @JsonProperty(FIELD_NAME_AUTHENTICATED) boolean authenticated,
                @Nullable @JsonProperty(FIELD_NAME_USER) String user,
                @Nullable @JsonProperty(FIELD_NAME_PRINCIPAL) String principal,
                @Nullable @JsonProperty(FIELD_NAME_TYPE) String type) {
            this.authenticated = authenticated;
            this.user = user;
            this.principal = principal;
            this.type = type;
        }

        static HistoryServerAuthenticatedUserResponseBody authenticated(
                HistoryServerAuthenticatedUser user) {
            return new HistoryServerAuthenticatedUserResponseBody(
                    true, user.getUserName(), user.getPrincipal(), user.getType());
        }

        static HistoryServerAuthenticatedUserResponseBody unauthenticated() {
            return new HistoryServerAuthenticatedUserResponseBody(false, null, null, null);
        }
    }
}
