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

import com.auth0.jwt.JWTSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.jackson.Jackson;
import ratpack.parse.ParserException;

public class LoginHandler<T> implements Handler {
    private final static Logger LOGGER = LoggerFactory.getLogger(LoginHandler.class);

    private final JWTSigner jwtSigner;
    private final JsonWebTokenModule.RealmConfig<T> config;

    public LoginHandler(JWTSigner jwtSigner,
                        JsonWebTokenModule.RealmConfig<T> config) {
        this.jwtSigner = jwtSigner;
        this.config = config;
    }

    @Override
    public void handle(Context context) throws Exception {
        try {
            final T credential = config.getInput(context);
            context.blocking(
                () -> config.authenticate(credential)
            ).onError(t -> {
                if (t.getClass().equals(AuthenticationFailed.class)) {
                    context.getResponse().status(401).send(t.getMessage());
                }
            }).then(claims -> {
                String token = jwtSigner.sign(claims.toMap());
                context.render(Jackson.json(token));
            });
        } catch (ParserException e) {
            LOGGER.info("Failed to parse Credential", e);
            context.getResponse().status(400).send();
        }
    }
}
