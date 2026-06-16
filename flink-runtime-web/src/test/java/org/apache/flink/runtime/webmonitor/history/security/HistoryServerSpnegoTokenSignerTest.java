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

import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.apache.hadoop.security.authentication.util.Signer;
import org.apache.hadoop.security.authentication.util.SignerSecretProvider;
import org.junit.jupiter.api.Test;

import javax.servlet.ServletContext;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests for {@link HistoryServerAuthenticationTokenSigner}. */
class HistoryServerSpnegoTokenSignerTest {

    private static final byte[] SECRET = "shared-secret".getBytes(StandardCharsets.UTF_8);

    @Test
    void shouldProduceHadoopAuthCompatibleSignature() throws Exception {
        AuthenticationToken token = createToken(System.currentTimeMillis() + 60_000L);

        String signedToken = new HistoryServerAuthenticationTokenSigner(SECRET).sign(token);
        String hadoopSignedToken =
                new Signer(new StaticSecretProvider(SECRET)).sign(token.toString());

        assertThat(signedToken).isEqualTo(hadoopSignedToken);
        assertThat(new Signer(new StaticSecretProvider(SECRET)).verifyAndExtract(signedToken))
                .isEqualTo(token.toString());
    }

    @Test
    void shouldVerifySignedToken() throws Exception {
        HistoryServerAuthenticationTokenSigner signer =
                new HistoryServerAuthenticationTokenSigner(SECRET);
        AuthenticationToken token = createToken(System.currentTimeMillis() + 60_000L);

        AuthenticationToken verifiedToken = signer.verifyAndExtract(signer.sign(token));

        assertThat(verifiedToken.getUserName()).isEqualTo("alice");
        assertThat(verifiedToken.getName()).isEqualTo("alice@EXAMPLE.COM");
        assertThat(verifiedToken.getType()).isEqualTo(HistoryServerSpnegoAuthenticator.TOKEN_TYPE);
        assertThat(verifiedToken.isExpired()).isFalse();
    }

    @Test
    void shouldRejectTamperedToken() {
        HistoryServerAuthenticationTokenSigner signer =
                new HistoryServerAuthenticationTokenSigner(SECRET);
        String signedToken = signer.sign(createToken(System.currentTimeMillis() + 60_000L));

        assertThatThrownBy(() -> signer.verifyAndExtract(signedToken + "tampered"))
                .isInstanceOf(AuthenticationException.class);
    }

    @Test
    void shouldStripCookieQuotesBeforeVerification() throws Exception {
        HistoryServerAuthenticationTokenSigner signer =
                new HistoryServerAuthenticationTokenSigner(SECRET);
        String signedToken = signer.sign(createToken(System.currentTimeMillis() + 60_000L));

        assertThat(signer.verifyAndExtract("\"" + signedToken + "\"").getUserName())
                .isEqualTo("alice");
    }

    @Test
    void shouldRejectEmptySecret() {
        assertThatThrownBy(() -> new HistoryServerAuthenticationTokenSigner(new byte[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("secret");
    }

    private static AuthenticationToken createToken(long expires) {
        AuthenticationToken token =
                new AuthenticationToken(
                        "alice", "alice@EXAMPLE.COM", HistoryServerSpnegoAuthenticator.TOKEN_TYPE);
        token.setExpires(expires);
        return token;
    }

    private static final class StaticSecretProvider extends SignerSecretProvider {

        private final byte[] secret;

        private StaticSecretProvider(byte[] secret) {
            this.secret = secret.clone();
        }

        @Override
        public void init(Properties config, ServletContext servletContext, long tokenValidity) {}

        @Override
        public byte[] getCurrentSecret() {
            return secret.clone();
        }

        @Override
        public byte[][] getAllSecrets() {
            return new byte[][] {secret.clone()};
        }
    }
}
