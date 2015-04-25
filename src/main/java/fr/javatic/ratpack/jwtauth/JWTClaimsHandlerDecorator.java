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

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.handling.HandlerDecorator;
import ratpack.registry.Registries;
import ratpack.registry.Registry;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Map;

class JWTClaimsHandlerDecorator implements HandlerDecorator {
    private final static Logger LOGGER = LoggerFactory.getLogger(JWTClaimsHandlerDecorator.class);

    private final JWTVerifier jwtVerifier;
    private final String header;

    JWTClaimsHandlerDecorator(JWTVerifier jwtVerifier, String header) {
        this.jwtVerifier = jwtVerifier;
        this.header = header;
    }

    @Override
    public Handler decorate(Registry serverRegistry, Handler rest) throws Exception {
        return this::handle;
    }

    public void handle(Context context) throws Exception {
        String tokens = context.getRequest().getHeaders().get(this.header);
        if (tokens == null) {
            context.next();
            return;
        }

        try {
            Map<String, Object> verify = jwtVerifier.verify(tokens);
            JWTClaims claims = new JWTClaims(verify);

            context.next(Registries.just(claims));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | JWTVerifyException e) {
            LOGGER.error("Failed to verify token", e);
            context.getResponse().status(500).send();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
