# Discontinued

As the excellent PAC4J lib (http://www.pac4j.org/#1 , https://github.com/pac4j/pac4j) now support JWT and ratpack provide good integration (http://ratpack.io/manual/current/pac4j.html#pac4j), I will not maintain this module.

# ratpack-jwtauth
Provide an easy to use Json Web Token authentication

Usage
------
Add the module to ratpack module through guice :

        bindingsSpec.add(JWTAuthModule.class, config -> {
            config.secret("someSalt");
            config.header("X-Authentication");
            config.authentication("default", UserRepository.class, AuthForm.class, InputType.JSON);
        });

Add login handler :

        path("login") {
            context.get(LoginHandlerProvider).handleLoginFor("default", context)
        }


Then to get the info :

        Chain mustBeIdentifiedChain = apiChain.handler(ctx -> {
            try {
                JWTClaims claims = ctx.get(JWTClaims.class);
                // check whatever you want
                ctx.next();
            } catch (NotInRegistryException e) {
                ctx.getResponse().status(403);
                ctx.render("Must be authentified");
            }
        });

Dependency.
------

Gradle

    repositories {
        maven {
            url "http://dl.bintray.com/ylemoigne/maven"
        }
    }

    dependencies {
        compile 'fr.javatic.ratpack:ratpack-jwtauth:0.2'
    }

Changelog.
------
* 0.1 : Initial Release
* 0.2 : Add ability for authentication function to return a custom http status code. Add ability to provide authentication function through injected class.
* 0.3 : upgrade to Ratpack 0.9.19
