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

import ratpack.exec.Blocking;
import ratpack.handling.Context;
import ratpack.jackson.Jackson;
import ratpack.jackson.JsonParseOpts;

public abstract class InputType {
    public final static InputType JSON = new JSONInputType();
    public final static InputType FORM = new FormInputType();

    public abstract <T> T getInput(Context ctx, Class<T> javaType) throws Exception;

    private static class JSONInputType extends InputType {
        @Override
        public <T> T getInput(Context context, Class<T> javaType) throws Exception {
            return Blocking.on(context.parse(Jackson.fromJson(javaType)));
        }
    }

    private static class FormInputType extends InputType {
        @Override
        public <T> T getInput(Context context, Class<T> javaType) throws Exception {
            return Blocking.on(context.parse(javaType));
        }
    }
}
