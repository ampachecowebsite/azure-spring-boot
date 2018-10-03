/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.microsoft.azure.spring.autoconfigure.aad;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

public class UserPrincipalManager {
    private static final Logger LOG = LoggerFactory.getLogger(UserPrincipalManager.class);

    private ServiceEndpoints serviceEndpoints;
    private ConfigurableJWTProcessor<SecurityContext> validator;
    private JWKSet jwsKeySet;

    public UserPrincipalManager(ServiceEndpoints serviceEndpoints) {
        this.serviceEndpoints = serviceEndpoints;
        this.validator = getAadJwtTokenValidator();
        this.jwsKeySet = loadAadPublicKeys();
    }

    public UserPrincipal buildUserPrincipal(String idToken) throws ParseException, JOSEException, BadJOSEException {
        final JWTClaimsSet jwtClaimsSet = validator.process(idToken, null);
        final JWTClaimsSetVerifier<SecurityContext> verifier = validator.getJWTClaimsSetVerifier();
        verifier.verify(jwtClaimsSet, null);
        final JWSObject jwsObject = JWSObject.parse(idToken);

        return new UserPrincipal.Builder().claims(jwtClaimsSet)
                .jwsObject(jwsObject)
                .jwsKeySet(jwsKeySet)
                .build();
    }

    private JWKSet loadAadPublicKeys() {
        try {
            return JWKSet.load(new URL(serviceEndpoints.getAadKeyDiscoveryUri()));
        } catch (IOException | ParseException e) {
            LOG.error("Error loading AAD public keys: {}", e.getMessage());
        }
        return null;
    }

    private ConfigurableJWTProcessor<SecurityContext> getAadJwtTokenValidator() {
        final ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWKSource<SecurityContext> keySource;

        try {
            keySource = new RemoteJWKSet<>(new URL(serviceEndpoints.getAadKeyDiscoveryUri()));
        } catch (MalformedURLException e) {
            LOG.error("Failed to parse active directory key discovery uri.", e);
            throw new IllegalStateException("Failed to parse active directory key discovery uri.", e);
        }

        final JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
        final JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<SecurityContext>() {
            @Override
            public void verify(JWTClaimsSet claimsSet, SecurityContext ctx) throws BadJWTException {
                super.verify(claimsSet, ctx);
                final String issuer = claimsSet.getIssuer();
                if (issuer == null || !issuer.contains("https://sts.windows.net/")
                        && !issuer.contains("https://sts.chinacloudapi.cn/")) {
                    throw new BadJWTException("Invalid token issuer");
                }
            }
        });
        return jwtProcessor;
    }
}
