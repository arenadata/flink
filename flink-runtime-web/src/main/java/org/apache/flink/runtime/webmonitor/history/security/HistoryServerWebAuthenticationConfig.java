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
import org.apache.flink.util.ConfigurationException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;

import static org.apache.flink.configuration.HistoryServerOptions
        .HISTORY_SERVER_WEB_AUTHENTICATION_COOKIE_PATH;
import static org.apache.flink.configuration.HistoryServerOptions
        .HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_KEYTAB;
import static org.apache.flink.configuration.HistoryServerOptions
        .HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_NAME_RULES;
import static org.apache.flink.configuration.HistoryServerOptions
        .HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL;
import static org.apache.flink.configuration.HistoryServerOptions
        .HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET;
import static org.apache.flink.configuration.HistoryServerOptions
        .HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET_FILE;
import static org.apache.flink.configuration.HistoryServerOptions
        .HISTORY_SERVER_WEB_AUTHENTICATION_TOKEN_VALIDITY;
import static org.apache.flink.configuration.HistoryServerOptions
        .HISTORY_SERVER_WEB_AUTHENTICATION_TYPE;

/** Parsed and validated HistoryServer web authentication configuration. */
final class HistoryServerWebAuthenticationConfig {

    private static final int RANDOM_SECRET_BYTES = 32;

    private final String kerberosPrincipal;
    private final Path kerberosKeytab;
    private final Optional<String> kerberosNameRules;
    private final Duration tokenValidity;
    private final String cookiePath;
    private final byte[] signatureSecret;

    private HistoryServerWebAuthenticationConfig(
            String kerberosPrincipal,
            Path kerberosKeytab,
            Optional<String> kerberosNameRules,
            Duration tokenValidity,
            String cookiePath,
            byte[] signatureSecret) {
        this.kerberosPrincipal = kerberosPrincipal;
        this.kerberosKeytab = kerberosKeytab;
        this.kerberosNameRules = kerberosNameRules;
        this.tokenValidity = tokenValidity;
        this.cookiePath = cookiePath;
        this.signatureSecret = signatureSecret.clone();
    }

    static Optional<HistoryServerWebAuthenticationConfig> from(Configuration configuration)
            throws ConfigurationException {
        HistoryServerWebAuthenticationType type = getAuthenticationType(configuration);
        if (type == HistoryServerWebAuthenticationType.NONE) {
            return Optional.empty();
        }
        if (type != HistoryServerWebAuthenticationType.KERBEROS) {
            throw new ConfigurationException(
                    "Unsupported "
                            + HISTORY_SERVER_WEB_AUTHENTICATION_TYPE.key()
                            + " value: "
                            + type);
        }

        return Optional.of(
                new HistoryServerWebAuthenticationConfig(
                        resolvePrincipal(
                                required(
                                        configuration,
                                        HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL)),
                        resolveKeytab(
                                required(
                                        configuration,
                                        HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_KEYTAB)),
                        optionalNonBlank(
                                configuration,
                                HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_NAME_RULES),
                        validateTokenValidity(
                                configuration.get(
                                        HISTORY_SERVER_WEB_AUTHENTICATION_TOKEN_VALIDITY)),
                        validateCookiePath(
                                configuration.get(HISTORY_SERVER_WEB_AUTHENTICATION_COOKIE_PATH)),
                        resolveSignatureSecret(configuration)));
    }

    String getKerberosPrincipal() {
        return kerberosPrincipal;
    }

    Path getKerberosKeytab() {
        return kerberosKeytab;
    }

    Optional<String> getKerberosNameRules() {
        return kerberosNameRules;
    }

    Duration getTokenValidity() {
        return tokenValidity;
    }

    String getCookiePath() {
        return cookiePath;
    }

    byte[] getSignatureSecret() {
        return signatureSecret.clone();
    }

    private static HistoryServerWebAuthenticationType getAuthenticationType(
            Configuration configuration) throws ConfigurationException {
        try {
            return configuration.get(HISTORY_SERVER_WEB_AUTHENTICATION_TYPE);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(
                    "Unsupported "
                            + HISTORY_SERVER_WEB_AUTHENTICATION_TYPE.key()
                            + " value.",
                    e);
        }
    }

    private static String resolvePrincipal(String principal) throws ConfigurationException {
        if ("*".equals(principal)) {
            return principal;
        }
        String resolvedPrincipal = principal.replace("_HOST", getLocalHostName());
        if (!resolvedPrincipal.startsWith("HTTP/")) {
            throw new ConfigurationException(
                    HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL.key()
                            + " must start with HTTP/ or be '*'.");
        }
        return resolvedPrincipal;
    }

    private static String getLocalHostName() throws ConfigurationException {
        try {
            return InetAddress.getLocalHost().getCanonicalHostName().toLowerCase(Locale.ROOT);
        } catch (UnknownHostException e) {
            throw new ConfigurationException(
                    "Could not resolve local hostname for HistoryServer SPNEGO principal.", e);
        }
    }

    private static Path resolveKeytab(String keytab) throws ConfigurationException {
        Path keytabPath = Paths.get(keytab);
        if (!Files.isRegularFile(keytabPath)) {
            throw new ConfigurationException(
                    HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_KEYTAB.key()
                            + " does not point to a regular file: "
                            + keytabPath);
        }
        return keytabPath;
    }

    private static Duration validateTokenValidity(Duration tokenValidity)
            throws ConfigurationException {
        if (tokenValidity == null || tokenValidity.isZero() || tokenValidity.isNegative()) {
            throw new ConfigurationException(
                    HISTORY_SERVER_WEB_AUTHENTICATION_TOKEN_VALIDITY.key()
                            + " must be greater than 0.");
        }
        return tokenValidity;
    }

    private static String validateCookiePath(String cookiePath) throws ConfigurationException {
        if (cookiePath == null || cookiePath.trim().isEmpty() || !cookiePath.startsWith("/")) {
            throw new ConfigurationException(
                    HISTORY_SERVER_WEB_AUTHENTICATION_COOKIE_PATH.key()
                            + " must be a non-empty absolute path.");
        }
        return cookiePath;
    }

    private static byte[] resolveSignatureSecret(Configuration configuration)
            throws ConfigurationException {
        Optional<String> configuredSecret =
                optionalNonBlank(configuration, HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET);
        Optional<String> configuredSecretFile =
                optionalNonBlank(
                        configuration, HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET_FILE);

        if (configuredSecret.isPresent() && configuredSecretFile.isPresent()) {
            throw new ConfigurationException(
                    "Only one of "
                            + HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET.key()
                            + " and "
                            + HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET_FILE.key()
                            + " may be configured.");
        }

        if (configuredSecret.isPresent()) {
            return configuredSecret.get().getBytes(StandardCharsets.UTF_8);
        }
        if (configuredSecretFile.isPresent()) {
            return readSecretFile(configuredSecretFile.get());
        }
        return createRandomSecret();
    }

    private static byte[] readSecretFile(String secretFile) throws ConfigurationException {
        try {
            String secret =
                    new String(Files.readAllBytes(Paths.get(secretFile)), StandardCharsets.UTF_8)
                            .trim();
            if (secret.isEmpty()) {
                throw new ConfigurationException(
                        HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET_FILE.key()
                                + " must not be empty.");
            }
            return secret.getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ConfigurationException(
                    "Could not read "
                            + HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET_FILE.key()
                            + ": "
                            + secretFile,
                    e);
        }
    }

    private static byte[] createRandomSecret() {
        byte[] secret = new byte[RANDOM_SECRET_BYTES];
        new SecureRandom().nextBytes(secret);
        return secret;
    }

    private static String required(
            Configuration configuration, org.apache.flink.configuration.ConfigOption<String> option)
            throws ConfigurationException {
        return optionalNonBlank(configuration, option)
                .orElseThrow(
                        () ->
                                new ConfigurationException(
                                        option.key()
                                                + " must be configured when "
                                                + HISTORY_SERVER_WEB_AUTHENTICATION_TYPE.key()
                                                + " is KERBEROS."));
    }

    private static Optional<String> optionalNonBlank(
            Configuration configuration,
            org.apache.flink.configuration.ConfigOption<String> option) {
        return configuration
                .getOptional(option)
                .map(String::trim)
                .filter(value -> !value.isEmpty());
    }
}
