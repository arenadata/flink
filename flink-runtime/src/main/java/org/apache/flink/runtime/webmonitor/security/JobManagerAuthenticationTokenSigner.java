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

import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

import static org.apache.flink.util.Preconditions.checkArgument;
import static org.apache.flink.util.Preconditions.checkNotNull;

/** Signs and verifies Hadoop-compatible JobManager web authentication tokens. */
final class JobManagerAuthenticationTokenSigner {

    static final String TOKEN_TYPE_KERBEROS = "kerberos";

    private static final String SIGNATURE_SEPARATOR = "&s=";
    private static final String SIGNING_ALGORITHM = "HmacSHA256";

    private final byte[] secret;
    private final Duration tokenValidity;
    private final Clock clock;

    JobManagerAuthenticationTokenSigner(byte[] secret, Duration tokenValidity, Clock clock) {
        this.secret = checkNotNull(secret, "secret must not be null").clone();
        checkArgument(this.secret.length > 0, "secret must not be empty");
        this.tokenValidity = checkNotNull(tokenValidity, "tokenValidity must not be null");
        this.clock = checkNotNull(clock, "clock must not be null");
    }

    String signToken(String userName, String principal) {
        AuthenticationToken token =
                new AuthenticationToken(userName, principal, TOKEN_TYPE_KERBEROS);
        token.setExpires(clock.millis() + tokenValidity.toMillis());
        return sign(token.toString());
    }

    Optional<AuthenticationToken> verifyToken(String signedToken) {
        if (signedToken == null || signedToken.isEmpty()) {
            return Optional.empty();
        }
        try {
            AuthenticationToken token =
                    AuthenticationToken.parse(verifyAndExtract(stripQuotes(signedToken)));
            if (!TOKEN_TYPE_KERBEROS.equals(token.getType())) {
                return Optional.empty();
            }
            if (token.getExpires() != -1 && clock.millis() > token.getExpires()) {
                return Optional.empty();
            }
            return Optional.of(token);
        } catch (AuthenticationException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private String sign(String rawToken) {
        return rawToken + SIGNATURE_SEPARATOR + computeSignature(rawToken);
    }

    private String verifyAndExtract(String signedToken) {
        int index = signedToken.lastIndexOf(SIGNATURE_SEPARATOR);
        if (index < 0) {
            throw new IllegalArgumentException("Authentication token is not signed.");
        }

        String rawToken = signedToken.substring(0, index);
        String expectedSignature = computeSignature(rawToken);
        String actualSignature = signedToken.substring(index + SIGNATURE_SEPARATOR.length());
        if (!MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                actualSignature.getBytes(StandardCharsets.UTF_8))) {
            throw new IllegalArgumentException("Authentication token signature is invalid.");
        }
        return rawToken;
    }

    private String computeSignature(String value) {
        try {
            Mac mac = Mac.getInstance(SIGNING_ALGORITHM);
            mac.init(new SecretKeySpec(secret, SIGNING_ALGORITHM));
            return Base64.getEncoder()
                    .encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(
                    "Could not sign JobManager web authentication token.", e);
        }
    }

    private static String stripQuotes(String value) {
        if (value != null
                && value.length() >= 2
                && value.startsWith("\"")
                && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }
}
