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

public class JWTAuthModule extends ConfigurableModule<JWTAuthModule.Config> {
    @Override
    protected void configure() {
        Multibinder.newSetBinder(binder(), HandlerDecorator.class)
            .addBinding()
            .to(JWTClaimsHandlerDecorator.class);
    }

    public static class Config {
        private Map<Object, RealmConfig<?>> mapRealmToRealmConfig = new HashMap<>();

        private String secret = UUID.randomUUID().toString();
        private String header = "X-Authorization";

        public <T> Config authentication(Object realm,
                                         Class<T> credentialType,
                                         AuthenticationFunction<T> function,
                                         InputType inputType) {
            this.mapRealmToRealmConfig.put(realm, new InstanceRealmConfig<>(credentialType, function, inputType));
            return this;
        }

        public <T> Config authentication(Object realm,
                                         Class<T> credentialType,
                                         Class<? extends AuthenticationFunction<T>> functionType,
                                         InputType inputType) {
            this.mapRealmToRealmConfig.put(realm, new TypeRealmConfig<>(credentialType, functionType, inputType));
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

        public String getHeader() {
            return header;
        }
    }

    public interface RealmConfig<T> {
        T getInput(Context context) throws Exception;

        JWTClaims authenticate(Injector inject, T credential) throws AuthenticationFailed;
    }

    public static class InstanceRealmConfig<T> implements RealmConfig<T> {
        private final AuthenticationFunction<T> function;
        private final Class<T> credentialType;
        private final InputType inputType;

        public InstanceRealmConfig(Class<T> credentialType,
                                   AuthenticationFunction<T> function,
                                   InputType inputType) {
            this.function = function;
            this.credentialType = credentialType;
            this.inputType = inputType;
        }

        public T getInput(Context context) throws Exception {
            return this.inputType.getInput(context, this.credentialType);
        }

        public JWTClaims authenticate(Injector inject, T credential) throws AuthenticationFailed {
            return this.function.authenticate(credential);
        }
    }

    public static class TypeRealmConfig<T> implements RealmConfig<T> {
        private final Class<? extends AuthenticationFunction<T>> functionType;
        private final Class<T> credentialType;
        private final InputType inputType;

        public TypeRealmConfig(Class<T> credentialType,
                               Class<? extends AuthenticationFunction<T>> functionType,
                               InputType inputType) {
            this.functionType = functionType;
            this.credentialType = credentialType;
            this.inputType = inputType;
        }

        public T getInput(Context context) throws Exception {
            return this.inputType.getInput(context, this.credentialType);
        }

        public JWTClaims authenticate(Injector injector, T credential) throws AuthenticationFailed {
            return injector.getInstance(functionType).authenticate(credential);
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
        config.mapRealmToRealmConfig.forEach((realm, realmConfig) -> {
            loginHandlerProvider.addAuthenticator(realm, new LoginHandler<>(jwtSigner, realmConfig, injector));
        });

        return loginHandlerProvider;
    }
}
