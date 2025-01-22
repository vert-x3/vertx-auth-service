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
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.impl.jose.JWT;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Apple.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface AppleIdAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Apple
   *
   * @param clientId   the client id given to you by Apple
   * @param teamId     the team id given to you by Apple
   * @param privateKey The private key for the client. This is the private key you generated when creating the
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String teamId, PubSecKeyOptions privateKey) {
    return create(vertx, clientId, teamId, privateKey, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Apple
   *
   * @param clientId          Client ID (also known as the Services ID in Apple's Developer Portal).
   * @param teamId            Team ID for the Apple Developer Account found on top right corner of the developers page
   * @param privateKey        The private key for the client. This is the private key you generated when creating the
   *                          App id. With the identifier for the private key at Apple
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String teamId, PubSecKeyOptions privateKey, HttpClientOptions httpClientOptions) {

    // create the client secret
    final JWT jwt = new JWT()
      .addJWK(new JWK(privateKey));

    final String clientSecret = jwt
      .sign(new JsonObject()
          .put("iss", teamId)
          .put("exp", System.currentTimeMillis() / 1000 + (86400 * 180)) // 6 months?
          .put("aud", "https://appleid.apple.com")
          .put("sub", clientId),
        new JWTOptions()
          .setAlgorithm("ES256")
          .setHeader(new JsonObject().put("keyid", privateKey.getId())));

    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setSite("https://appleid.apple.com")
        .setTokenPath("/auth/token")
        .setRevocationPath("/auth/revoke")
        .setAuthorizationPath("/auth/authorize")
        .setJwkPath("/auth/keys")
        .setUseBasicAuthorization(false));
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the default site in the
   * configuration options and attempt to load the well known descriptor. If a site is provided (for example when
   * running on a custom instance) that site will be used to do the lookup.
   * <p>
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @param vertx  the vertx instance
   * @param config the initial config
   * @return future with instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final PubSecKeyOptions privateKey, final OAuth2Options config) {
    // don't override if already set
    final String site = config.getSite() == null ? "https://appleid.apple.com" : config.getSite();

    // create the client secret
    final JWT jwt = new JWT()
      .addJWK(new JWK(privateKey));

    final String clientSecret = jwt
      .sign(new JsonObject()
          .put("iss", config.getTenant())
          .put("exp", System.currentTimeMillis() / 1000 + (86400 * 180)) // 6 months?
          .put("aud", "https://appleid.apple.com")
          .put("sub", config.getClientId()),
        new JWTOptions()
          .setAlgorithm("ES256"));

    return OpenIDConnectAuth.discover(
      vertx,
      new OAuth2Options(config)
        .setSite(site)
        .setClientSecret(clientSecret));
  }
}
