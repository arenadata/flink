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
import org.apache.flink.configuration.WebOptions;
import org.apache.flink.configuration.WebOptions.WebAuthenticationType;
import org.apache.flink.util.ConfigurationException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests for {@link JobManagerWebAuthenticationConfig}. */
class JobManagerWebAuthenticationConfigTest {

    @TempDir private Path tempDir;

    @Test
    void shouldReturnEmptyConfigWhenAuthenticationIsDisabled() throws Exception {
        assertThat(JobManagerWebAuthenticationConfig.fromConfiguration(new Configuration()))
                .isEmpty();
    }

    @Test
    void shouldRejectInvalidAuthenticationType() {
        Configuration configuration = new Configuration();
        configuration.setString(WebOptions.AUTHENTICATION_TYPE.key(), "BASIC");

        assertThatThrownBy(() -> JobManagerWebAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(WebOptions.AUTHENTICATION_TYPE.key());
    }

    @Test
    void shouldRequirePrincipalWhenKerberosIsEnabled() throws Exception {
        Configuration configuration = kerberosConfiguration();
        configuration.set(WebOptions.AUTHENTICATION_KERBEROS_KEYTAB, createKeytab().toString());

        assertThatThrownBy(() -> JobManagerWebAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(WebOptions.AUTHENTICATION_KERBEROS_PRINCIPAL.key());
    }

    @Test
    void shouldRequireKeytabWhenKerberosIsEnabled() {
        Configuration configuration = kerberosConfiguration();
        configuration.set(
                WebOptions.AUTHENTICATION_KERBEROS_PRINCIPAL, "HTTP/localhost@EXAMPLE.COM");

        assertThatThrownBy(() -> JobManagerWebAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(WebOptions.AUTHENTICATION_KERBEROS_KEYTAB.key());
    }

    @Test
    void shouldResolveHostPlaceholderInPrincipalFromRestAddress() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(WebOptions.AUTHENTICATION_KERBEROS_PRINCIPAL, "HTTP/_HOST@EXAMPLE.COM");
        configuration.set(RestOptions.ADDRESS, "localhost");

        JobManagerWebAuthenticationConfig config =
                JobManagerWebAuthenticationConfig.fromConfiguration(configuration).orElseThrow();

        assertThat(config.getKerberosPrincipal())
                .startsWith("HTTP/")
                .endsWith("@EXAMPLE.COM")
                .doesNotContain("_HOST");
    }

    @Test
    void shouldResolveHostPlaceholderFromBindAddressWhenRestAddressIsWildcard() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(WebOptions.AUTHENTICATION_KERBEROS_PRINCIPAL, "HTTP/_HOST@EXAMPLE.COM");
        configuration.set(RestOptions.ADDRESS, "0.0.0.0");
        configuration.set(RestOptions.BIND_ADDRESS, "localhost");

        JobManagerWebAuthenticationConfig config =
                JobManagerWebAuthenticationConfig.fromConfiguration(configuration).orElseThrow();

        assertThat(config.getKerberosPrincipal())
                .startsWith("HTTP/")
                .endsWith("@EXAMPLE.COM")
                .doesNotContain("_HOST")
                .doesNotContain("0.0.0.0");
    }

    @Test
    void shouldAllowWildcardPrincipal() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(WebOptions.AUTHENTICATION_KERBEROS_PRINCIPAL, "*");

        JobManagerWebAuthenticationConfig config =
                JobManagerWebAuthenticationConfig.fromConfiguration(configuration).orElseThrow();

        assertThat(config.getKerberosPrincipal()).isEqualTo("*");
    }

    @Test
    void shouldUseDefaultNameRules() throws Exception {
        JobManagerWebAuthenticationConfig config =
                JobManagerWebAuthenticationConfig.fromConfiguration(validKerberosConfiguration())
                        .orElseThrow();

        assertThat(config.getKerberosNameRules()).isEqualTo("DEFAULT");
    }

    @Test
    void shouldRejectNonHttpPrincipal() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(
                WebOptions.AUTHENTICATION_KERBEROS_PRINCIPAL, "flink/localhost@EXAMPLE.COM");

        assertThatThrownBy(() -> JobManagerWebAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("must start with HTTP/");
    }

    @Test
    void shouldRejectInvalidCookiePath() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(WebOptions.AUTHENTICATION_COOKIE_PATH, "flink");

        assertThatThrownBy(() -> JobManagerWebAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(WebOptions.AUTHENTICATION_COOKIE_PATH.key());
    }

    @Test
    void shouldRejectNonPositiveTokenValidity() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(WebOptions.AUTHENTICATION_TOKEN_VALIDITY, Duration.ZERO);

        assertThatThrownBy(() -> JobManagerWebAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(WebOptions.AUTHENTICATION_TOKEN_VALIDITY.key());
    }

    @Test
    void shouldRejectUnreadableKeytabPath() throws Exception {
        Configuration configuration = kerberosConfiguration();
        configuration.set(
                WebOptions.AUTHENTICATION_KERBEROS_PRINCIPAL, "HTTP/localhost@EXAMPLE.COM");
        configuration.set(
                WebOptions.AUTHENTICATION_KERBEROS_KEYTAB,
                tempDir.resolve("missing.keytab").toString());

        assertThatThrownBy(() -> JobManagerWebAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining(WebOptions.AUTHENTICATION_KERBEROS_KEYTAB.key());
    }

    @Test
    void shouldRejectMultipleSignatureSecretSources() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(WebOptions.AUTHENTICATION_SIGNATURE_SECRET, "secret");
        configuration.set(
                WebOptions.AUTHENTICATION_SIGNATURE_SECRET_FILE,
                createSecretFile("secret").toString());

        assertThatThrownBy(() -> JobManagerWebAuthenticationConfig.fromConfiguration(configuration))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("Only one of");
    }

    @Test
    void shouldLoadSignatureSecretFromFile() throws Exception {
        Configuration configuration = validKerberosConfiguration();
        configuration.set(
                WebOptions.AUTHENTICATION_SIGNATURE_SECRET_FILE,
                createSecretFile("shared-secret\n").toString());

        JobManagerWebAuthenticationConfig config =
                JobManagerWebAuthenticationConfig.fromConfiguration(configuration).orElseThrow();

        assertThat(new String(config.getSignatureSecret(), StandardCharsets.UTF_8))
                .isEqualTo("shared-secret");
    }

    private Configuration validKerberosConfiguration() throws Exception {
        Configuration configuration = kerberosConfiguration();
        configuration.set(
                WebOptions.AUTHENTICATION_KERBEROS_PRINCIPAL, "HTTP/localhost@EXAMPLE.COM");
        configuration.set(WebOptions.AUTHENTICATION_KERBEROS_KEYTAB, createKeytab().toString());
        return configuration;
    }

    private static Configuration kerberosConfiguration() {
        Configuration configuration = new Configuration();
        configuration.set(WebOptions.AUTHENTICATION_TYPE, WebAuthenticationType.KERBEROS);
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
