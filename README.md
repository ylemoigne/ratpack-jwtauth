# ratpack-jwtauth
Provide an easy to use Json Web Token authentication

Usage
------
Add the module to ratpack module through guice :

        bindingsSpec.add(JsonWebTokenModule.class, config -> {
            config.secret("someSalt");
            config.header("X-Authentication");
            config.authentication("default", UserRepository.class, AuthForm.class, InputType.JSON);
        });

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
0.1 : Initial Release
0.2 : Add ability for authentication function to return a custom http status code. Add ability to provide authentication function through injected class.