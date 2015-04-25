/*
 * Copyright (c) 2015 Yann Le Moigne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.javatic.ratpack.jwtauth;

import java.time.Instant;
import java.util.*;

/**
 * JWT Claims according to https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1
 */
public class JWTClaims {
    private Map<String, Object> claims;

    public JWTClaims() {
        claims = new HashMap<>();
        claims.put("iat", System.currentTimeMillis());
        claims.put("jti", UUID.randomUUID().toString());
    }

    public JWTClaims(Map<String, Object> verify) {
        this.claims = new HashMap<>();
        this.claims.putAll(verify);
    }

    public JWTClaims setIssuer(String issuer) {
        claims.put("iss", issuer);
        return this;
    }

    public JWTClaims setSubject(String subject) {
        claims.put("sub", subject);
        return this;
    }

    public JWTClaims setAudience(String... audiences) {
        claims.put("aud", audiences);
        return this;
    }

    public JWTClaims setExpirationTime(Instant instant) {
        claims.put("exp", instant.toEpochMilli());
        return this;
    }

    public JWTClaims setNotBefore(Instant instant) {
        claims.put("nbf", instant.toEpochMilli());
        return this;
    }

    public JWTClaims set(String string, Object value) {
        claims.put("private." + string, value);
        return this;
    }

    public String getIssuer() {
        return (String) claims.get("iss");
    }

    public String getSubject() {
        return (String) claims.get("sub");
    }

    public List<String> getAudience() {
        return Arrays.asList((String[]) claims.get("aud"));
    }

    public Instant getExpirationTime() {
        return Instant.ofEpochMilli((long) claims.get("exp"));
    }

    public Instant getNotBefore(Instant instant) {
        return Instant.ofEpochMilli((long) claims.get("nbf"));
    }

    public <T> T get(String key) {
        //noinspection unchecked
        return (T) claims.get("private." + key);
    }

    public Map<String, Object> toMap() {
        return Collections.unmodifiableMap(this.claims);
    }
}
