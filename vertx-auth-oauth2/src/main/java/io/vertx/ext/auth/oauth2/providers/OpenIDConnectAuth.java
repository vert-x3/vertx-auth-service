/*
 * Copyright 2015 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;

/**
 * Simplified factory to create an {@link io.vertx.ext.auth.oauth2.OAuth2Auth} for OpenID Connect.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the given site in the
   * configuration options and attempt to load the well known descriptor.
   * <p>
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @param vertx  the vertx instance
   * @param config the initial config, it should contain a site url
   * @return future with the instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final OAuth2Options config) {
    if (config.getSite() == null) {
      return Future.failedFuture("issuer cannot be null");
    }

    // compute paths with variables, at this moment it is only relevant that
    // the paths and site are properly computed
    config.replaceVariables(false);

    final String oidc_discovery_path = "/.well-known/openid-configuration";

    // The site and issuer are used interchangeably here and can be confusing in some cases. A small replacement can
    // happen at this time to ensure that the config is correct.
    String issuer = config.getSite();
    if (issuer.endsWith(oidc_discovery_path)) {
      issuer = issuer.substring(0, issuer.length() - oidc_discovery_path.length());
    }

    final SimpleHttpClient httpClient = new SimpleHttpClient(
      vertx,
      config.getUserAgent(),
      config.getHttpClientOptions());

    // the response follows the OpenID Connect provider metadata spec:
    // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    return httpClient.fetch(
        HttpMethod.GET,
        issuer + oidc_discovery_path,
        new JsonObject()
          .put("Accept", "application/json"),
        null)
      .compose(response -> {
        if (response.statusCode() != 200) {
          return Future.failedFuture("Bad Response [" + response.statusCode() + "] " + response.body());
        }

        if (!response.is("application/json")) {
          return Future.failedFuture("Cannot handle Content-Type: " + response.headers().get("Content-Type"));
        }

        final JsonObject json = response.jsonObject();

        if (json == null) {
          return Future.failedFuture("Cannot handle null JSON");
        }

        // some providers return errors as JSON too
        if (json.containsKey("error")) {
          // attempt to handle the error as a string
          return Future.failedFuture(json.getString("error_description", json.getString("error")));
        }

        // issuer validation
        if (config.isValidateIssuer()) {
          String issuerEndpoint = json.getString("issuer");
          if (issuerEndpoint != null) {
            // the provider is letting the user know the issuer endpoint, so we need to validate
            // as in vertx oauth the issuer (site config) is a url without the trailing slash we
            // will compare the received endpoint without the final slash is present
            if (issuerEndpoint.endsWith("/")) {
              issuerEndpoint = issuerEndpoint.substring(0, issuerEndpoint.length() - 1);
            }

            if (!config.getSite().equals(issuerEndpoint)) {
              return Future.failedFuture("issuer validation failed: received [" + issuerEndpoint + "]");
            }
          }
        }

        config.setAuthorizationPath(json.getString("authorization_endpoint"));
        config.setTokenPath(json.getString("token_endpoint"));
        config.setLogoutPath(json.getString("end_session_endpoint"));
        config.setRevocationPath(json.getString("revocation_endpoint"));
        config.setUserInfoPath(json.getString("userinfo_endpoint"));
        config.setJwkPath(json.getString("jwks_uri"));
        config.setIntrospectionPath(json.getString("introspection_endpoint"));

        if (json.containsKey("issuer")) {
          // the discovery document includes the issuer, this means we can and should assert that source of all tokens
          // when in JWT form
          JWTOptions jwtOptions = config.getJWTOptions();
          if (jwtOptions == null) {
            jwtOptions = new JWTOptions();
            config.setJWTOptions(jwtOptions);
          }
          // configure the issuer
          jwtOptions.setIssuer(json.getString("issuer"));
        }

        if (json.containsKey("grant_types_supported")) {
          // reset config
          config.setSupportedGrantTypes(null);
          // optional config
          JsonArray flows = json.getJsonArray("grant_types_supported");
          flows.forEach(el -> config.addSupportedGrantType((String) el));
        }

        // configure client authentication
        if (json.containsKey("token_endpoint_auth_methods_supported")) {
          // optional
          JsonArray methods = json.getJsonArray("token_endpoint_auth_methods_supported");
          if (methods.contains("client_secret_basic")) {
            // preferred
            config.setUseBasicAuthorization(true);
          } else if (methods.contains("client_secret_post")) {
            config.setUseBasicAuthorization(false);
          } else {
            // default to what is defined by the callee
          }
        }

        try {
          // the constructor might fail if the configuration is incomplete
          final OAuth2Auth oidc = OAuth2Auth.create(vertx, config);

          if (config.getJwkPath() != null) {
            return oidc
              .jWKSet()
              .map(oidc);
          } else {
            return Future.succeededFuture(oidc);
          }
        } catch (IllegalArgumentException | IllegalStateException e) {
          return Future.failedFuture(e);
        }
      })
      .andThen(v -> {
        // Close the client but also keep a reference to it, so it's not garbage collected
        httpClient.close();
      });
  }
}
