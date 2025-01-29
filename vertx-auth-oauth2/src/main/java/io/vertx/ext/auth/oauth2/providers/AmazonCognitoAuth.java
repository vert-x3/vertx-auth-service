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
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Amazon Cognito.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface AmazonCognitoAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Amazon Cognito
   *
   * @param region       the region to use
   * @param clientId     the client id given to you by Amazon Cognito
   * @param clientSecret the client secret given to you by Amazon Cognito
   * @param domain       the Cognito domain
   * @param guid         the guid of your application given to you by Amazon Cognito
   */
  static OAuth2Auth create(Vertx vertx, String region, String clientId, String clientSecret, String domain, String guid) {
    return create(vertx, region, clientId, clientSecret, domain, guid, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Amazon Cognito
   *
   * @param region            the region to use
   * @param clientId          the client id given to you by Amazon Cognito
   * @param clientSecret      the client secret given to you by Amazon Cognito
   * @param domain            the Cognito domain
   * @param userPoolId        the userPoolId of your application given to you by Amazon Cognito
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String region, String clientId, String clientSecret, String domain, String userPoolId, HttpClientOptions httpClientOptions) {
    if (region == null) {
      throw new IllegalStateException("region cannot be null");
    }

    final String siteBase = String.format("https://cognito-idp.%s.amazonaws.com", region);
    final String domainUrl = String.format("https://%s.auth.%s.amazoncognito.com", domain, region);

    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setTenant(userPoolId)
        .setSite(siteBase + "/{tenant}")
        .setTokenPath(domainUrl + "/oauth2/token")
        .setAuthorizationPath(domainUrl + "/oauth2/authorize")
        .setUserInfoPath(domainUrl + "/oauth2/userInfo")
        .setRevocationPath(domainUrl + "/oauth/revoke")
        .setJwkPath(siteBase + "/{tenant}/.well-known/jwks.json")
        .setLogoutPath(domainUrl + "/logout")
        .setScopeSeparator(" ")
        .setJWTOptions(new JWTOptions().setIssuer(siteBase + "/{tenant}")));
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
   * @see AmazonCognitoAuth#discover(Vertx, OAuth2Options, Handler)
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final OAuth2Options config) {
    return OpenIDConnectAuth.discover(
      vertx,
      new OAuth2Options(config)
        .setScopeSeparator("+"));
  }
}
