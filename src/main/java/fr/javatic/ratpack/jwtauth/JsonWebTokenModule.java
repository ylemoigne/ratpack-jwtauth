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
import com.auth0.jwt.JWTVerifier;
import com.google.inject.Injector;
import com.google.inject.Provides;
import com.google.inject.multibindings.Multibinder;
import ratpack.guice.ConfigurableModule;
import ratpack.handling.Context;
import ratpack.handling.HandlerDecorator;

import javax.inject.Singleton;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class JsonWebTokenModule extends ConfigurableModule<JsonWebTokenModule.Config> {
    @Override
    protected void configure() {
        Multibinder.newSetBinder(binder(), HandlerDecorator.class)
            .addBinding()
            .toInstance(new JWTClaimsHandlerDecorator(
                getProvider(JWTVerifier.class).get(),
                getProvider(Config.class).get().header
            ));
    }

    public static class Config {
        private Map<Object, RealmConfig<?>> mapRealmToAuthenticationFunction = new HashMap<>();

        private String secret = UUID.randomUUID().toString();
        private String header = "X-Authorization";

        public <T> Config authentication(Object realm,
                                         AuthenticationFunction<T> function,
                                         Class<T> credentialType,
                                         InputType inputType) {
            this.mapRealmToAuthenticationFunction.put(realm, new RealmConfig<>(function, credentialType, inputType));
            return this;
        }

        public Config secret(String secret) {
            this.secret = secret;
            return this;
        }

        public Config header(String header) {
            this.header = header;
            return this;
        }
    }

    public static class RealmConfig<T> {
        private final AuthenticationFunction<T> function;
        private final Class<T> credentialType;
        private final InputType inputType;

        public RealmConfig(AuthenticationFunction<T> function,
                           Class<T> credentialType,
                           InputType inputType) {
            this.function = function;
            this.credentialType = credentialType;
            this.inputType = inputType;
        }

        public T getInput(Context context) throws Exception {
            return this.inputType.getInput(context, this.credentialType);
        }

        public JWTClaims authenticate(T credential) throws AuthenticationFailed {
            return this.function.authenticate(credential);
        }
    }

    @Provides
    @Singleton
    protected JWTVerifier jwtVerifier(Config config) {
        return new JWTVerifier(config.secret);
    }

    @Provides
    @Singleton
    protected JWTSigner jwtSigner(Config config) {
        return new JWTSigner(config.secret);
    }

    @Provides
    @com.google.inject.Singleton
    private LoginHandlerProvider loginHandlerProvider(Config config, JWTSigner jwtSigner, Injector injector) {
        LoginHandlerProvider loginHandlerProvider = new LoginHandlerProvider();
        config.mapRealmToAuthenticationFunction.forEach((realm, realmConfig) -> {
            loginHandlerProvider.addAuthenticator(realm, new LoginHandler<>(jwtSigner, realmConfig));
        });

        return loginHandlerProvider;
    }
}
