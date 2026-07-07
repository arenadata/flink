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
import org.apache.flink.configuration.RestOptions;
import org.apache.flink.configuration.SecurityOptions;
import org.apache.flink.configuration.WebOptions.WebAuthenticationType;
import org.apache.flink.util.ConfigurationException;
import org.apache.flink.util.StringUtils;

import org.apache.hadoop.security.authentication.util.KerberosUtil;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;

import static org.apache.flink.configuration.WebOptions.AUTHENTICATION_COOKIE_PATH;
import static org.apache.flink.configuration.WebOptions.AUTHENTICATION_KERBEROS_KEYTAB;
import static org.apache.flink.configuration.WebOptions.AUTHENTICATION_KERBEROS_NAME_RULES;
import static org.apache.flink.configuration.WebOptions.AUTHENTICATION_KERBEROS_PRINCIPAL;
import static org.apache.flink.configuration.WebOptions.AUTHENTICATION_SIGNATURE_SECRET;
import static org.apache.flink.configuration.WebOptions.AUTHENTICATION_SIGNATURE_SECRET_FILE;
import static org.apache.flink.configuration.WebOptions.AUTHENTICATION_TOKEN_VALIDITY;
import static org.apache.flink.configuration.WebOptions.AUTHENTICATION_TYPE;

/** Parsed and validated JobManager web authentication configuration. */
final class JobManagerWebAuthenticationConfig {

    private static final int RANDOM_SECRET_BYTES = 32;

    private final String kerberosPrincipal;
    private final Path kerberosKeytab;
    private final String kerberosNameRules;
    private final Duration tokenValidity;
    private final String cookiePath;
    private final byte[] signatureSecret;
    private final boolean secureCookie;

    private JobManagerWebAuthenticationConfig(
            String kerberosPrincipal,
            Path kerberosKeytab,
            String kerberosNameRules,
            Duration tokenValidity,
            String cookiePath,
            byte[] signatureSecret,
            boolean secureCookie) {
        this.kerberosPrincipal = kerberosPrincipal;
        this.kerberosKeytab = kerberosKeytab;
        this.kerberosNameRules = kerberosNameRules;
        this.tokenValidity = tokenValidity;
        this.cookiePath = cookiePath;
        this.signatureSecret = signatureSecret.clone();
        this.secureCookie = secureCookie;
    }

    static Optional<JobManagerWebAuthenticationConfig> fromConfiguration(
            Configuration configuration) throws ConfigurationException {
        WebAuthenticationType type = getAuthenticationType(configuration);
        if (type == WebAuthenticationType.NONE) {
            return Optional.empty();
        }
        if (type != WebAuthenticationType.KERBEROS) {
            throw new ConfigurationException(
                    "Unsupported " + AUTHENTICATION_TYPE.key() + " value: " + type);
        }

        return Optional.of(
                new JobManagerWebAuthenticationConfig(
                        resolvePrincipal(
                                required(configuration, AUTHENTICATION_KERBEROS_PRINCIPAL),
                                configuration),
                        resolveKeytab(required(configuration, AUTHENTICATION_KERBEROS_KEYTAB)),
                        configuration.get(AUTHENTICATION_KERBEROS_NAME_RULES),
                        validateTokenValidity(configuration.get(AUTHENTICATION_TOKEN_VALIDITY)),
                        validateCookiePath(configuration.get(AUTHENTICATION_COOKIE_PATH)),
                        resolveSignatureSecret(configuration),
                        SecurityOptions.isRestSSLEnabled(configuration)));
    }

    String getKerberosPrincipal() {
        return kerberosPrincipal;
    }

    Path getKerberosKeytab() {
        return kerberosKeytab;
    }

    String getKerberosNameRules() {
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

    boolean isSecureCookie() {
        return secureCookie;
    }

    private static WebAuthenticationType getAuthenticationType(Configuration configuration)
            throws ConfigurationException {
        try {
            return configuration.get(AUTHENTICATION_TYPE);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(
                    "Unsupported " + AUTHENTICATION_TYPE.key() + " value.", e);
        }
    }

    private static String resolvePrincipal(String principal, Configuration configuration)
            throws ConfigurationException {
        if ("*".equals(principal)) {
            return principal;
        }
        String resolvedPrincipal = principal.replace("_HOST", resolveHostName(configuration));
        if (!resolvedPrincipal.startsWith("HTTP/")) {
            throw new ConfigurationException(
                    AUTHENTICATION_KERBEROS_PRINCIPAL.key() + " must start with HTTP/ or be '*'.");
        }
        return resolvedPrincipal;
    }

    private static String resolveHostName(Configuration configuration)
            throws ConfigurationException {
        Optional<String> configuredHost =
                firstUsableHost(
                        configuration.getOptional(RestOptions.ADDRESS),
                        configuration.getOptional(RestOptions.BIND_ADDRESS));
        if (configuredHost.isPresent()) {
            try {
                return InetAddress.getByName(configuredHost.get())
                        .getCanonicalHostName()
                        .toLowerCase(Locale.ROOT);
            } catch (UnknownHostException e) {
                throw new ConfigurationException(
                        "Could not resolve _HOST in JobManager web Kerberos principal.", e);
            }
        }
        try {
            return KerberosUtil.getLocalHostName().toLowerCase(Locale.ROOT);
        } catch (UnknownHostException e) {
            throw new ConfigurationException(
                    "Could not resolve local hostname for JobManager web Kerberos principal.", e);
        }
    }

    @SafeVarargs
    private static Optional<String> firstUsableHost(Optional<String>... hosts) {
        for (Optional<String> host : hosts) {
            Optional<String> usableHost =
                    host.map(String::trim)
                            .filter(value -> !value.isEmpty())
                            .filter(value -> !isWildcardAddress(value));
            if (usableHost.isPresent()) {
                return usableHost;
            }
        }
        return Optional.empty();
    }

    private static boolean isWildcardAddress(String value) {
        return "0.0.0.0".equals(value) || "::".equals(value) || "[::]".equals(value);
    }

    private static Path resolveKeytab(String keytab) throws ConfigurationException {
        Path keytabPath = Path.of(keytab);
        if (!Files.isRegularFile(keytabPath) || !Files.isReadable(keytabPath)) {
            throw new ConfigurationException(
                    AUTHENTICATION_KERBEROS_KEYTAB.key()
                            + " does not point to a readable regular file: "
                            + keytabPath);
        }
        return keytabPath;
    }

    private static Duration validateTokenValidity(Duration tokenValidity)
            throws ConfigurationException {
        if (tokenValidity == null || tokenValidity.isZero() || tokenValidity.isNegative()) {
            throw new ConfigurationException(
                    AUTHENTICATION_TOKEN_VALIDITY.key() + " must be greater than 0.");
        }
        return tokenValidity;
    }

    private static String validateCookiePath(String cookiePath) throws ConfigurationException {
        if (StringUtils.isNullOrWhitespaceOnly(cookiePath) || !cookiePath.startsWith("/")) {
            throw new ConfigurationException(
                    AUTHENTICATION_COOKIE_PATH.key() + " must be a non-empty absolute path.");
        }
        return cookiePath;
    }

    private static byte[] resolveSignatureSecret(Configuration configuration)
            throws ConfigurationException {
        Optional<String> configuredSecret =
                optionalNonBlank(configuration, AUTHENTICATION_SIGNATURE_SECRET);
        Optional<String> configuredSecretFile =
                optionalNonBlank(configuration, AUTHENTICATION_SIGNATURE_SECRET_FILE);

        if (configuredSecret.isPresent() && configuredSecretFile.isPresent()) {
            throw new ConfigurationException(
                    "Only one of "
                            + AUTHENTICATION_SIGNATURE_SECRET.key()
                            + " and "
                            + AUTHENTICATION_SIGNATURE_SECRET_FILE.key()
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
            String secret = Files.readString(Path.of(secretFile), StandardCharsets.UTF_8).trim();
            if (secret.isEmpty()) {
                throw new ConfigurationException(
                        AUTHENTICATION_SIGNATURE_SECRET_FILE.key() + " must not be empty.");
            }
            return secret.getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ConfigurationException(
                    "Could not read "
                            + AUTHENTICATION_SIGNATURE_SECRET_FILE.key()
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
                                                + AUTHENTICATION_TYPE.key()
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
