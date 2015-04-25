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
import com.google.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    @Inject
    JWTClaimsHandlerDecorator(JWTVerifier jwtVerifier, JWTAuthModule.Config config) {
        this.jwtVerifier = jwtVerifier;
        this.header = config.getHeader();
    }

    @Override
    public Handler decorate(Registry serverRegistry, Handler rest) throws Exception {
        return context -> {
            String tokens = context.getRequest().getHeaders().get(this.header);
            if (tokens == null) {
                context.insert(rest);
                return;
            }

            try {
                Map<String, Object> verify = jwtVerifier.verify(tokens);
                JWTClaims claims = new JWTClaims(verify);

                context.insert(Registries.just(claims), rest);
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | JWTVerifyException e) {
                LOGGER.error("Failed to verify token", e);
                context.getResponse().status(500).send();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        };
    }
}
