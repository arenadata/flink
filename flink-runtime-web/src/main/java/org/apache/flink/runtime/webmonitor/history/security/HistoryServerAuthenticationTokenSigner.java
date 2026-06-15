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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

/** Signs and verifies Hadoop Auth compatible HistoryServer authentication tokens. */
final class HistoryServerAuthenticationTokenSigner {

    private static final String SIGNATURE_SEPARATOR = "&s=";
    private static final String SIGNING_ALGORITHM = "HmacSHA256";

    private final byte[] secret;

    HistoryServerAuthenticationTokenSigner(byte[] secret) {
        this.secret = Objects.requireNonNull(secret, "secret must not be null").clone();
        if (this.secret.length == 0) {
            throw new IllegalArgumentException("secret must not be empty");
        }
    }

    String sign(AuthenticationToken token) {
        return sign(token.toString());
    }

    String sign(String token) {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("token must not be empty");
        }
        return token + SIGNATURE_SEPARATOR + computeSignature(token);
    }

    AuthenticationToken verifyAndExtract(String signedToken) throws AuthenticationException {
        String token = verifyAndExtractRaw(stripQuotes(signedToken));
        return AuthenticationToken.parse(token);
    }

    String verifyAndExtractRaw(String signedToken) throws AuthenticationException {
        if (signedToken == null || signedToken.isEmpty()) {
            throw new AuthenticationException("Missing authentication token");
        }
        int index = signedToken.lastIndexOf(SIGNATURE_SEPARATOR);
        if (index == -1) {
            throw new AuthenticationException("Invalid signed authentication token");
        }

        String token = signedToken.substring(0, index);
        String expectedSignature = computeSignature(token);
        String actualSignature = signedToken.substring(index + SIGNATURE_SEPARATOR.length());

        if (!MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                actualSignature.getBytes(StandardCharsets.UTF_8))) {
            throw new AuthenticationException("Invalid authentication token signature");
        }
        return token;
    }

    private String computeSignature(String token) {
        try {
            Mac mac = Mac.getInstance(SIGNING_ALGORITHM);
            mac.init(new SecretKeySpec(secret, SIGNING_ALGORITHM));
            byte[] signature = mac.doFinal(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Could not sign authentication token.", e);
        }
    }

    private static String stripQuotes(String value) {
        if (value != null && value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }
}
