/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.microsoft.azure.spring.autoconfigure.aad;

import com.google.common.collect.Lists;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;

import java.io.Serializable;
import java.util.*;

public class UserPrincipal implements Serializable {
    private JWKSet jwsKeySet;
    private JWSObject jwsObject;
    private JWTClaimsSet jwtClaimsSet;
    private List<UserGroup> userGroups = Lists.newArrayList();

    public static class Builder {
        private JWKSet jwsKeySet;
        private JWSObject jwsObject;
        private JWTClaimsSet jwtClaimsSet;

        public Builder() {
        }

        public Builder jwsKeySet(JWKSet jwsKeySet) {
            this.jwsKeySet = jwsKeySet;
            return this;
        }

        public Builder jwsObject(JWSObject jwsObject) {
            this.jwsObject = jwsObject;
            return this;
        }

        public Builder claims(JWTClaimsSet jwtClaimsSet) {
            this.jwtClaimsSet = jwtClaimsSet;
            return this;
        }

        public UserPrincipal build() {
           return new UserPrincipal(this);
        }
    }

    private UserPrincipal(Builder builder) {
        this.jwsKeySet = builder.jwsKeySet;
        this.jwsObject = builder.jwsObject;
        this.jwtClaimsSet = builder.jwtClaimsSet;
    }

    // claimset
    public String getIssuer() {
        return jwtClaimsSet == null ? null : jwtClaimsSet.getIssuer();
    }

    public String getSubject() {
        return jwtClaimsSet == null ? null : jwtClaimsSet.getSubject();
    }

    public Map<String, Object> getClaims() {
        return jwtClaimsSet == null ? null : jwtClaimsSet.getClaims();
    }

    public Object getClaim() {
        return jwtClaimsSet == null ? null : jwtClaimsSet.getClaim("tid");
    }

    // header
    public String getKid() {
        return jwsObject == null ? null : jwsObject.getHeader().getKeyID();
    }

    // JWK
    public JWK getJWKByKid(String kid) {
        return jwsKeySet == null ? null : jwsKeySet.getKeyByKeyId(kid);
    }

    public void setUserGroups(List<UserGroup> groups) {
        this.userGroups = groups;
    }

    public List<UserGroup> getUserGroups() {
        return this.userGroups;
    }

    public boolean isMemberOf(UserGroup group) {
        return !(userGroups == null || userGroups.isEmpty()) && userGroups.contains(group);
    }
}

