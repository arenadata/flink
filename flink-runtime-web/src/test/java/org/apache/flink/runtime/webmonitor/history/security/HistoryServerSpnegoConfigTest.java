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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests for {@link HistoryServerWebAuthenticationConfig}. */
class HistoryServerSpnegoConfigTest {

    @TempDir private Path tempDir;

    @Test
    void shouldReturnEmptyConfigWhenAuthenticationIsDisabled() throws Exception {
        assertThat(HistoryServerWebAuthenticationConfig.from(new Configuration())).isEmpty();
    }

    @Test
    void shouldRequirePrincipalWhenKerberosIsEnabled() throws Exception {
        Configuration configuration = kerberosConfiguration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_KEYTAB,
                createKeytab().toString());

        assertThatThrownBy(() -> HistoryServerWebAuthenticationConfig.from(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(
                        HistoryServerOptions
                                .HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL
                                .key());
    }

    @Test
    void shouldRejectInvalidAuthenticationType() {
        Configuration configuration = new Configuration();
        configuration.setString(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_TYPE.key(), "BASIC");

        assertThatThrownBy(() -> HistoryServerWebAuthenticationConfig.from(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(
                        HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_TYPE.key());
    }

    @Test
    void shouldRequireKeytabWhenKerberosIsEnabled() {
        Configuration configuration = kerberosConfiguration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL,
                "HTTP/localhost@EXAMPLE.COM");

        assertThatThrownBy(() -> HistoryServerWebAuthenticationConfig.from(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(
                        HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_KEYTAB
                                .key());
    }

    @Test
    void shouldResolveHostPlaceholderInPrincipal() throws Exception {
        Configuration configuration = kerberosConfiguration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL,
                "HTTP/_HOST@EXAMPLE.COM");
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_KEYTAB,
                createKeytab().toString());

        HistoryServerWebAuthenticationConfig config =
                HistoryServerWebAuthenticationConfig.from(configuration).orElseThrow();

        assertThat(config.getKerberosPrincipal())
                .startsWith("HTTP/")
                .endsWith("@EXAMPLE.COM")
                .doesNotContain("_HOST");
    }

    @Test
    void shouldRejectNonHttpPrincipal() throws Exception {
        Configuration configuration = kerberosConfiguration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL,
                "flink/localhost@EXAMPLE.COM");
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_KEYTAB,
                createKeytab().toString());

        assertThatThrownBy(() -> HistoryServerWebAuthenticationConfig.from(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("must start with HTTP/");
    }

    @Test
    void shouldRejectInvalidCookiePath() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_COOKIE_PATH,
                "history");

        assertThatThrownBy(() -> HistoryServerWebAuthenticationConfig.from(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(
                        HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_COOKIE_PATH.key());
    }

    @Test
    void shouldRejectNonPositiveTokenValidity() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_TOKEN_VALIDITY,
                Duration.ZERO);

        assertThatThrownBy(() -> HistoryServerWebAuthenticationConfig.from(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(
                        HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_TOKEN_VALIDITY
                                .key());
    }

    @Test
    void shouldRejectMultipleSignatureSecretSources() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET,
                "secret");
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET_FILE,
                createSecretFile("secret").toString());

        assertThatThrownBy(() -> HistoryServerWebAuthenticationConfig.from(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("Only one of");
    }

    @Test
    void shouldLoadSignatureSecretFromFile() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_SIGNATURE_SECRET_FILE,
                createSecretFile("shared-secret\n").toString());

        HistoryServerWebAuthenticationConfig config =
                HistoryServerWebAuthenticationConfig.from(configuration).orElseThrow();

        assertThat(new String(config.getSignatureSecret(), StandardCharsets.UTF_8))
                .isEqualTo("shared-secret");
    }

    private Configuration validKerberosConfiguration() throws Exception {
        Configuration configuration = kerberosConfiguration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL,
                "HTTP/localhost@EXAMPLE.COM");
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_KERBEROS_KEYTAB,
                createKeytab().toString());
        return configuration;
    }

    private Configuration kerberosConfiguration() {
        Configuration configuration = new Configuration();
        configuration.set(
                HistoryServerOptions.HISTORY_SERVER_WEB_AUTHENTICATION_TYPE,
                HistoryServerWebAuthenticationType.KERBEROS);
        return configuration;
    }

    private Path createKeytab() throws Exception {
        return Files.createFile(tempDir.resolve("test-" + System.nanoTime() + ".keytab"));
    }

    private Path createSecretFile(String secret) throws Exception {
        Path secretFile = tempDir.resolve("secret-" + System.nanoTime());
        return Files.write(secretFile, secret.getBytes(StandardCharsets.UTF_8));
    }
}
