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

import ratpack.handling.Context;

import java.util.HashMap;
import java.util.Map;

public class LoginHandlerProvider {
    private final Map<Object, LoginHandler> authenticators = new HashMap<>();

    LoginHandlerProvider() {
    }

    void addAuthenticator(Object realm, LoginHandler loginHandler) {
        authenticators.put(realm, loginHandler);
    }

    public void handleLoginFor(Object realm, Context ctx) {
        ctx.insert(authenticators.get(realm));
    }
}
