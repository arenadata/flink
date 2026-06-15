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
import org.apache.flink.runtime.security.KerberosUtils;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.FullHttpRequest;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.cookie.Cookie;
import org.apache.flink.shaded.netty4.io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import org.apache.flink.util.ConfigurationException;

import org.apache.hadoop.security.authentication.client.AuthenticatedURL;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.client.KerberosAuthenticator;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.apache.hadoop.security.authentication.util.KerberosUtil;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import java.io.File;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.time.Clock;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Performs Kerberos/SPNEGO authentication for the Flink HistoryServer web endpoint. */
final class HistoryServerSpnegoAuthenticator {

    static final String TOKEN_TYPE = "kerberos";

    private static final Logger LOG = LoggerFactory.getLogger(HistoryServerSpnegoAuthenticator.class);
    private static final Pattern HTTP_PRINCIPAL_PATTERN = Pattern.compile("HTTP/.*");

    private final Map<String, Subject> serverSubjects;
    private final GSSManager gssManager;
    private final HistoryServerAuthenticationTokenSigner tokenSigner;
    private final long tokenValidityMillis;
    private final String cookiePath;
    private final Clock clock;

    private HistoryServerSpnegoAuthenticator(
            Map<String, Subject> serverSubjects,
            GSSManager gssManager,
            HistoryServerAuthenticationTokenSigner tokenSigner,
            long tokenValidityMillis,
            String cookiePath,
            Clock clock) {
        this.serverSubjects = serverSubjects;
        this.gssManager = gssManager;
        this.tokenSigner = tokenSigner;
        this.tokenValidityMillis = tokenValidityMillis;
        this.cookiePath = cookiePath;
        this.clock = clock;
    }

    static Optional<HistoryServerSpnegoAuthenticator> fromConfiguration(Configuration configuration)
            throws ConfigurationException {
        Optional<HistoryServerWebAuthenticationConfig> config =
                HistoryServerWebAuthenticationConfig.from(configuration);
        if (!config.isPresent()) {
            return Optional.empty();
        }
        return Optional.of(fromConfig(config.get(), Clock.systemUTC()));
    }

    static HistoryServerSpnegoAuthenticator fromConfig(
            HistoryServerWebAuthenticationConfig config, Clock clock) throws ConfigurationException {
        Map<String, Subject> serverSubjects = createServerSubjects(config);
        return new HistoryServerSpnegoAuthenticator(
                serverSubjects,
                GSSManager.getInstance(),
                new HistoryServerAuthenticationTokenSigner(config.getSignatureSecret()),
                config.getTokenValidity().toMillis(),
                config.getCookiePath(),
                clock);
    }

    HistoryServerAuthenticationResult authenticate(FullHttpRequest request) {
        Optional<String> cookieValue = getAuthenticationCookie(request);
        if (cookieValue.isPresent()) {
            try {
                AuthenticationToken token = tokenSigner.verifyAndExtract(cookieValue.get());
                if (TOKEN_TYPE.equals(token.getType()) && !token.isExpired()) {
                    return HistoryServerAuthenticationResult.authenticated(token.getUserName());
                }
                LOG.debug("Ignoring invalid or expired HistoryServer authentication cookie.");
            } catch (AuthenticationException | IllegalArgumentException e) {
                LOG.debug("Ignoring invalid HistoryServer authentication cookie.", e);
            }
        }

        String authorization = request.headers().get(KerberosAuthenticator.AUTHORIZATION);
        if (authorization == null || !startsWithNegotiate(authorization)) {
            return HistoryServerAuthenticationResult.unauthorized();
        }

        String encodedToken =
                authorization.substring(KerberosAuthenticator.NEGOTIATE.length()).trim();
        if (encodedToken.isEmpty()) {
            return HistoryServerAuthenticationResult.forbidden();
        }

        final byte[] clientToken;
        try {
            clientToken = Base64.getDecoder().decode(encodedToken);
        } catch (IllegalArgumentException e) {
            LOG.debug("Received malformed SPNEGO token.", e);
            return HistoryServerAuthenticationResult.forbidden();
        }

        try {
            String serverPrincipal = KerberosUtil.getTokenServerName(clientToken);
            if (!serverPrincipal.startsWith("HTTP/")) {
                LOG.warn("Rejecting SPNEGO token for non-HTTP service principal.");
                return HistoryServerAuthenticationResult.forbidden();
            }
            Subject serverSubject = serverSubjects.get(serverPrincipal);
            if (serverSubject == null) {
                LOG.warn(
                        "Rejecting SPNEGO token for an unconfigured HistoryServer service principal.");
                return HistoryServerAuthenticationResult.forbidden();
            }
            return Subject.doAs(
                    serverSubject,
                    (PrivilegedExceptionAction<HistoryServerAuthenticationResult>)
                            () -> authenticate(serverPrincipal, clientToken));
        } catch (PrivilegedActionException e) {
            LOG.debug("SPNEGO authentication failed.", e.getException());
            return HistoryServerAuthenticationResult.forbidden();
        } catch (RuntimeException e) {
            LOG.debug("SPNEGO authentication failed.", e);
            return HistoryServerAuthenticationResult.forbidden();
        }
    }

    String createAuthenticationCookie(String signedToken, boolean secure) {
        StringBuilder cookie =
                new StringBuilder(AuthenticatedURL.AUTH_COOKIE)
                        .append("=\"")
                        .append(signedToken)
                        .append("\"; Path=")
                        .append(cookiePath)
                        .append("; HttpOnly");
        if (secure) {
            cookie.append("; Secure");
        }
        return cookie.toString();
    }

    String createExpiredAuthenticationCookie(boolean secure) {
        StringBuilder cookie =
                new StringBuilder(AuthenticatedURL.AUTH_COOKIE)
                        .append("=; Path=")
                        .append(cookiePath)
                        .append("; Max-Age=0; HttpOnly");
        if (secure) {
            cookie.append("; Secure");
        }
        return cookie.toString();
    }

    HistoryServerAuthenticationTokenSigner getTokenSigner() {
        return tokenSigner;
    }

    private HistoryServerAuthenticationResult authenticate(String serverPrincipal, byte[] clientToken)
            throws GSSException, IOException {
        GSSContext gssContext = null;
        GSSCredential gssCredential = null;
        try {
            gssCredential =
                    gssManager.createCredential(
                            gssManager.createName(
                                    serverPrincipal, KerberosUtil.NT_GSS_KRB5_PRINCIPAL_OID),
                            GSSCredential.INDEFINITE_LIFETIME,
                            new Oid[] {
                                KerberosUtil.GSS_SPNEGO_MECH_OID, KerberosUtil.GSS_KRB5_MECH_OID
                            },
                            GSSCredential.ACCEPT_ONLY);
            gssContext = gssManager.createContext(gssCredential);
            byte[] serverToken = gssContext.acceptSecContext(clientToken, 0, clientToken.length);
            if (!gssContext.isEstablished()) {
                return HistoryServerAuthenticationResult.unauthorized(encode(serverToken));
            }

            String clientPrincipal = gssContext.getSrcName().toString();
            String userName = new KerberosName(clientPrincipal).getShortName();
            AuthenticationToken authenticationToken =
                    new AuthenticationToken(userName, clientPrincipal, TOKEN_TYPE);
            authenticationToken.setExpires(clock.millis() + tokenValidityMillis);
            return HistoryServerAuthenticationResult.authenticated(
                    userName, tokenSigner.sign(authenticationToken));
        } finally {
            if (gssContext != null) {
                gssContext.dispose();
            }
            if (gssCredential != null) {
                gssCredential.dispose();
            }
        }
    }

    private static Optional<String> encode(byte[] token) {
        if (token == null || token.length == 0) {
            return Optional.empty();
        }
        return Optional.of(Base64.getEncoder().encodeToString(token));
    }

    private static boolean startsWithNegotiate(String authorization) {
        return authorization.regionMatches(
                true,
                0,
                KerberosAuthenticator.NEGOTIATE,
                0,
                KerberosAuthenticator.NEGOTIATE.length());
    }

    private static Optional<String> getAuthenticationCookie(FullHttpRequest request) {
        for (String cookieHeader : request.headers().getAll(HttpHeaderNames.COOKIE)) {
            try {
                Set<Cookie> cookies = ServerCookieDecoder.STRICT.decode(cookieHeader);
                for (Cookie cookie : cookies) {
                    if (AuthenticatedURL.AUTH_COOKIE.equals(cookie.name())) {
                        return Optional.of(cookie.value());
                    }
                }
            } catch (IllegalArgumentException e) {
                LOG.debug("Ignoring malformed HistoryServer Cookie header.", e);
            }
        }
        return Optional.empty();
    }

    private static Map<String, Subject> createServerSubjects(
            HistoryServerWebAuthenticationConfig config)
            throws ConfigurationException {
        Map<String, Subject> subjects = new HashMap<>();
        for (String principal : resolveServerPrincipals(config)) {
            subjects.put(
                    principal, loginServerSubject(config.getKerberosKeytab().toFile(), principal));
        }
        configureKerberosNameRules(config);
        return Collections.unmodifiableMap(subjects);
    }

    private static void configureKerberosNameRules(HistoryServerWebAuthenticationConfig config)
            throws ConfigurationException {
        try {
            KerberosName.setRules(config.getKerberosNameRules().orElse("DEFAULT"));
            KerberosName.setRuleMechanism(KerberosName.DEFAULT_MECHANISM);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(
                    "Invalid HistoryServer SPNEGO Kerberos name rules.", e);
        }
    }

    private static Subject loginServerSubject(File keytabFile, String principal)
            throws ConfigurationException {
        Subject subject = new Subject();
        LoginContext loginContext;
        try {
            loginContext =
                    new LoginContext(
                            "",
                            subject,
                            (CallbackHandler) null,
                            new javax.security.auth.login.Configuration() {
                                @Override
                                public AppConfigurationEntry[] getAppConfigurationEntry(
                                        String name) {
                                    return new AppConfigurationEntry[] {
                                        acceptorKeytabEntry(keytabFile, principal)
                                    };
                                }
                            });
            loginContext.login();
        } catch (LoginException e) {
            throw new ConfigurationException(
                    "Could not log in HistoryServer SPNEGO principal "
                            + principal
                            + " from keytab "
                            + keytabFile,
                    e);
        }
        LOG.info("Using HistoryServer SPNEGO principal {} from keytab {}", principal, keytabFile);
        return loginContext.getSubject();
    }

    private static AppConfigurationEntry acceptorKeytabEntry(File keytabFile, String principal) {
        Map<String, String> kerberosOptions = new HashMap<>();
        if (KerberosUtils.getKrb5LoginModuleName().contains("ibm")) {
            kerberosOptions.put("useKeytab", keytabFile.toURI().toString());
            kerberosOptions.put("credsType", "both");
        } else {
            kerberosOptions.put("keyTab", keytabFile.getAbsolutePath());
            kerberosOptions.put("doNotPrompt", "true");
            kerberosOptions.put("useKeyTab", "true");
            kerberosOptions.put("storeKey", "true");
            kerberosOptions.put("isInitiator", "false");
        }

        kerberosOptions.put("principal", principal);
        kerberosOptions.put("refreshKrb5Config", "true");

        return new AppConfigurationEntry(
                KerberosUtils.getKrb5LoginModuleName(),
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                kerberosOptions);
    }

    private static String[] resolveServerPrincipals(HistoryServerWebAuthenticationConfig config)
            throws ConfigurationException {
        if (!"*".equals(config.getKerberosPrincipal())) {
            return new String[] {config.getKerberosPrincipal()};
        }
        try {
            String[] principals =
                    KerberosUtil.getPrincipalNames(
                            config.getKerberosKeytab().toString(), HTTP_PRINCIPAL_PATTERN);
            if (principals.length == 0) {
                throw new ConfigurationException(
                        "No HTTP principals were found in "
                                + config.getKerberosKeytab()
                                + " for HistoryServer SPNEGO authentication.");
            }
            return principals;
        } catch (IOException e) {
            throw new ConfigurationException(
                    "Could not read HistoryServer SPNEGO principals from "
                            + config.getKerberosKeytab(),
                    e);
        }
    }
}
