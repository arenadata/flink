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

package org.apache.flink.table.gateway.rest.util;

import org.apache.flink.annotation.PublicEvolving;
import org.apache.flink.configuration.ConfigOption;
import org.apache.flink.table.gateway.rest.SqlGatewayRestEndpoint;

import java.time.Duration;

import static org.apache.flink.configuration.ConfigOptions.key;

/**
 * Options to configure {@link SqlGatewayRestEndpoint}.
 *
 * <p>By default, the user must select a local address to set ADDRESS, then the server will bind the
 * address to all the local IPV4 address (0.0.0.0) and bind the port to BIND_PORT(fallback to the
 * default value of PORT).
 *
 * <p>1. If user specifies BIND_ADDRESS, then the server will bind to BIND_ADDRESS and suggest the
 * user that the current client should connect to this BIND_ADDRESS rather than ADDRESS in the log.
 *
 * <p>2. If user specifies PORT, then the server will bind the port to BIND_PORT(fallback to the
 * value of PORT).
 *
 * <p>3. If user specifies BIND_PORT, then the server will ignore PORT and directly bind the port to
 * the value of BIND_PORT.
 */
@PublicEvolving
public class SqlGatewayRestOptions {

    /** Authentication mechanism for the SQL Gateway REST endpoint. */
    public enum SqlGatewayRestAuthenticationType {
        NONE,
        KERBEROS
    }

    /** The address that should be used by clients to connect to the sql gateway server. */
    public static final ConfigOption<String> ADDRESS =
            key("address")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "The address that should be used by clients to connect to the sql gateway server.");

    /** The address that the sql gateway server binds itself to. */
    public static final ConfigOption<String> BIND_ADDRESS =
            key("bind-address")
                    .stringType()
                    .noDefaultValue()
                    .withDescription("The address that the sql gateway server binds itself.");

    /** The port range that the sql gateway server could bind itself to. */
    public static final ConfigOption<String> BIND_PORT =
            key("bind-port")
                    .stringType()
                    .defaultValue("8083")
                    .withDescription(
                            "The port that the sql gateway server binds itself. Accepts a list of ports (“50100,50101”), ranges"
                                    + " (“50100-50200”) or a combination of both. It is recommended to set a range of ports to avoid"
                                    + " collisions when multiple sql gateway servers are running on the same machine.");

    /** The port that the client connects to. */
    public static final ConfigOption<Integer> PORT =
            key("port")
                    .intType()
                    .defaultValue(8083)
                    .withDescription(
                            String.format(
                                    "The port that the client connects to. If %s has not been specified, then the sql gateway server will bind to this port.",
                                    BIND_PORT.key()));

    /** Authentication type used by the SQL Gateway REST endpoint. */
    public static final ConfigOption<SqlGatewayRestAuthenticationType> AUTHENTICATION_TYPE =
            key("authentication.type")
                    .enumType(SqlGatewayRestAuthenticationType.class)
                    .defaultValue(SqlGatewayRestAuthenticationType.NONE)
                    .withDescription(
                            "The authentication type for the SQL Gateway REST endpoint. "
                                    + "Supported values are NONE and KERBEROS.");

    /** Kerberos principal used by the SQL Gateway REST endpoint SPNEGO acceptor. */
    public static final ConfigOption<String> AUTHENTICATION_KERBEROS_PRINCIPAL =
            key("authentication.kerberos.principal")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "Kerberos principal used by the SQL Gateway REST endpoint SPNEGO acceptor. "
                                    + "The HTTP/_HOST@REALM pattern is supported, and '*' uses all HTTP principals from the keytab.");

    /** Kerberos keytab used by the SQL Gateway REST endpoint SPNEGO acceptor. */
    public static final ConfigOption<String> AUTHENTICATION_KERBEROS_KEYTAB =
            key("authentication.kerberos.keytab")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "Kerberos keytab used by the SQL Gateway REST endpoint SPNEGO acceptor.");

    /** Kerberos auth-to-local rules used by the SQL Gateway REST endpoint. */
    public static final ConfigOption<String> AUTHENTICATION_KERBEROS_NAME_RULES =
            key("authentication.kerberos.name-rules")
                    .stringType()
                    .defaultValue("DEFAULT")
                    .withDescription(
                            "Kerberos auth-to-local rules used to derive the local user name from the authenticated Kerberos principal.");

    /** Validity period of the SQL Gateway REST authentication cookie. */
    public static final ConfigOption<Duration> AUTHENTICATION_TOKEN_VALIDITY =
            key("authentication.token.validity")
                    .durationType()
                    .defaultValue(Duration.ofHours(10))
                    .withDescription(
                            "Validity period of the SQL Gateway REST authentication cookie.");

    /** Cookie path used for SQL Gateway REST authentication cookies. */
    public static final ConfigOption<String> AUTHENTICATION_COOKIE_PATH =
            key("authentication.cookie.path")
                    .stringType()
                    .defaultValue("/")
                    .withDescription(
                            "Cookie path used for SQL Gateway REST authentication cookies.");

    /** Shared secret used to sign SQL Gateway REST authentication cookies. */
    public static final ConfigOption<String> AUTHENTICATION_SIGNATURE_SECRET =
            key("authentication.signature.secret")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "Shared secret used to sign SQL Gateway REST authentication cookies. "
                                    + "If neither this option nor authentication.signature.secret-file is configured, a random per-process secret is used.");

    /** File containing the shared secret used to sign SQL Gateway REST authentication cookies. */
    public static final ConfigOption<String> AUTHENTICATION_SIGNATURE_SECRET_FILE =
            key("authentication.signature.secret-file")
                    .stringType()
                    .noDefaultValue()
                    .withDescription(
                            "File containing the shared secret used to sign SQL Gateway REST authentication cookies. "
                                    + "If neither this option nor authentication.signature.secret is configured, a random per-process secret is used.");
}
