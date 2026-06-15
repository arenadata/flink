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

import org.apache.flink.configuration.Configuration;
import org.apache.flink.configuration.DelegatingConfiguration;
import org.apache.flink.configuration.SecurityOptions;
import org.apache.flink.table.gateway.api.endpoint.SqlGatewayEndpointFactoryUtils;
import org.apache.flink.table.gateway.rest.SqlGatewayRestEndpointFactory;
import org.apache.flink.table.gateway.rest.util.SqlGatewayRestOptions;
import org.apache.flink.table.gateway.rest.util.SqlGatewayRestOptions.SqlGatewayRestAuthenticationType;
import org.apache.flink.util.ConfigurationException;
import org.apache.flink.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;

import static org.apache.flink.util.Preconditions.checkNotNull;

/** Parsed SQL Gateway REST authentication configuration. */
final class SqlGatewayRestAuthenticationConfig {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SqlGatewayRestAuthenticationType type;
    private final String principal;
    private final String keytab;
    private final String nameRules;
    private final Duration tokenValidity;
    private final String cookiePath;
    private final byte[] signatureSecret;
    private final boolean secureCookie;
    private final String restAddress;

    private SqlGatewayRestAuthenticationConfig(
            SqlGatewayRestAuthenticationType type,
            String principal,
            String keytab,
            String nameRules,
            Duration tokenValidity,
            String cookiePath,
            byte[] signatureSecret,
            boolean secureCookie,
            String restAddress) {
        this.type = checkNotNull(type);
        this.principal = principal;
        this.keytab = keytab;
        this.nameRules = checkNotNull(nameRules);
        this.tokenValidity = checkNotNull(tokenValidity);
        this.cookiePath = checkNotNull(cookiePath);
        this.signatureSecret = signatureSecret.clone();
        this.secureCookie = secureCookie;
        this.restAddress = checkNotNull(restAddress);
    }

    static SqlGatewayRestAuthenticationConfig fromConfiguration(Configuration configuration)
            throws ConfigurationException {
        Configuration endpointConfig =
                new DelegatingConfiguration(
                        configuration,
                        SqlGatewayEndpointFactoryUtils.getSqlGatewayOptionPrefix(
                                SqlGatewayRestEndpointFactory.IDENTIFIER));

        SqlGatewayRestAuthenticationType type =
                endpointConfig.get(SqlGatewayRestOptions.AUTHENTICATION_TYPE);
        boolean secureCookie = SecurityOptions.isRestSSLEnabled(configuration);
        String restAddress = configuration.get(org.apache.flink.configuration.RestOptions.ADDRESS);
        if (type == SqlGatewayRestAuthenticationType.NONE) {
            return new SqlGatewayRestAuthenticationConfig(
                    type,
                    null,
                    null,
                    SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_NAME_RULES.defaultValue(),
                    SqlGatewayRestOptions.AUTHENTICATION_TOKEN_VALIDITY.defaultValue(),
                    SqlGatewayRestOptions.AUTHENTICATION_COOKIE_PATH.defaultValue(),
                    new byte[0],
                    secureCookie,
                    restAddress);
        }

        String principal =
                endpointConfig.get(SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_PRINCIPAL);
        String keytab = endpointConfig.get(SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_KEYTAB);
        String nameRules =
                endpointConfig.get(SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_NAME_RULES);
        Duration tokenValidity =
                endpointConfig.get(SqlGatewayRestOptions.AUTHENTICATION_TOKEN_VALIDITY);
        String cookiePath = endpointConfig.get(SqlGatewayRestOptions.AUTHENTICATION_COOKIE_PATH);
        String signatureSecret =
                endpointConfig.get(SqlGatewayRestOptions.AUTHENTICATION_SIGNATURE_SECRET);
        String signatureSecretFile =
                endpointConfig.get(SqlGatewayRestOptions.AUTHENTICATION_SIGNATURE_SECRET_FILE);

        if (!tokenValidity.isPositive()) {
            throw new ConfigurationException(
                    String.format(
                            "SQL Gateway REST authentication option '%s' must be positive.",
                            fullKey(SqlGatewayRestOptions.AUTHENTICATION_TOKEN_VALIDITY.key())));
        }
        if (StringUtils.isNullOrWhitespaceOnly(cookiePath) || !cookiePath.startsWith("/")) {
            throw new ConfigurationException(
                    String.format(
                            "SQL Gateway REST authentication option '%s' must start with '/'.",
                            fullKey(SqlGatewayRestOptions.AUTHENTICATION_COOKIE_PATH.key())));
        }

        byte[] secret = resolveSignatureSecret(signatureSecret, signatureSecretFile);
        requireNonEmpty(principal, SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_PRINCIPAL.key());
        requireNonEmpty(keytab, SqlGatewayRestOptions.AUTHENTICATION_KERBEROS_KEYTAB.key());

        return new SqlGatewayRestAuthenticationConfig(
                type,
                principal,
                keytab,
                nameRules,
                tokenValidity,
                cookiePath,
                secret,
                secureCookie,
                restAddress);
    }

    private static byte[] resolveSignatureSecret(String secret, String secretFile)
            throws ConfigurationException {
        boolean hasSecret = !StringUtils.isNullOrWhitespaceOnly(secret);
        boolean hasSecretFile = !StringUtils.isNullOrWhitespaceOnly(secretFile);
        if (hasSecret && hasSecretFile) {
            throw new ConfigurationException(
                    String.format(
                            "Only one of SQL Gateway REST authentication options '%s' and '%s' can be configured.",
                            fullKey(SqlGatewayRestOptions.AUTHENTICATION_SIGNATURE_SECRET.key()),
                            fullKey(
                                    SqlGatewayRestOptions.AUTHENTICATION_SIGNATURE_SECRET_FILE
                                            .key())));
        }
        if (hasSecret) {
            return secret.getBytes(StandardCharsets.UTF_8);
        }
        if (hasSecretFile) {
            try {
                String fileSecret =
                        Files.readString(Path.of(secretFile), StandardCharsets.UTF_8).trim();
                if (fileSecret.isEmpty()) {
                    throw new ConfigurationException(
                            String.format(
                                    "SQL Gateway REST authentication option '%s' points to an empty file.",
                                    fullKey(
                                            SqlGatewayRestOptions
                                                    .AUTHENTICATION_SIGNATURE_SECRET_FILE
                                                    .key())));
                }
                return fileSecret.getBytes(StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new ConfigurationException(
                        String.format(
                                "Could not read SQL Gateway REST authentication secret file configured by '%s'.",
                                fullKey(
                                        SqlGatewayRestOptions
                                                .AUTHENTICATION_SIGNATURE_SECRET_FILE
                                                .key())),
                        e);
            }
        }

        byte[] randomSecret = new byte[32];
        SECURE_RANDOM.nextBytes(randomSecret);
        return randomSecret;
    }

    private static void requireNonEmpty(String value, String localKey) throws ConfigurationException {
        if (StringUtils.isNullOrWhitespaceOnly(value)) {
            throw new ConfigurationException(
                    String.format(
                            "SQL Gateway REST authentication option '%s' is required when '%s' is KERBEROS.",
                            fullKey(localKey),
                            fullKey(SqlGatewayRestOptions.AUTHENTICATION_TYPE.key())));
        }
    }

    private static String fullKey(String localKey) {
        return SqlGatewayEndpointFactoryUtils.getSqlGatewayOptionPrefix(
                        SqlGatewayRestEndpointFactory.IDENTIFIER)
                + localKey;
    }

    SqlGatewayRestAuthenticationType type() {
        return type;
    }

    boolean isKerberosEnabled() {
        return type == SqlGatewayRestAuthenticationType.KERBEROS;
    }

    String principal() {
        return principal;
    }

    String keytab() {
        return keytab;
    }

    String nameRules() {
        return nameRules;
    }

    Duration tokenValidity() {
        return tokenValidity;
    }

    String cookiePath() {
        return cookiePath;
    }

    byte[] signatureSecret() {
        return signatureSecret.clone();
    }

    boolean secureCookie() {
        return secureCookie;
    }

    String restAddress() {
        return restAddress;
    }
}
