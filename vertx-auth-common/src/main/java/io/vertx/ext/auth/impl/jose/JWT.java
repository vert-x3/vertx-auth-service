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
package io.vertx.ext.auth.impl.jose;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.internal.logging.Logger;
import io.vertx.core.internal.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.NoSuchKeyIdException;
import io.vertx.ext.auth.impl.CertificateHelper;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static io.vertx.ext.auth.impl.Codec.*;

/**
 * JWT and JWS implementation draft-ietf-oauth-json-web-token-32.
 *
 * @author Paulo Lopes
 */
public final class JWT {

  private static final Logger LOG = LoggerFactory.getLogger(JWT.class);

  /**
   * Internal holder of keys and usage tracking
   */
  private static class KeyRing implements Iterable<JWS> {
    private final List<JWS> signers = new ArrayList<>();
    private int cnt = 0;

    int size() {
      return signers.size();
    }

    JWS get(int pos) {
      return signers.get(pos);
    }

    JWS get() {
      int size = signers.size();
      switch (size) {
        case 0:
          return null;
        case 1:
          return signers.get(0);
        default:
          return signers.get(cnt++ % size);
      }
    }

    JWS set(int pos, JWS jws) {
      return signers.set(pos, jws);
    }

    boolean add(JWS jws) {
      return signers.add(jws);
    }

    @Override
    public Iterator<JWS> iterator() {
      return signers.iterator();
    }
  }

  private static final Charset UTF8 = StandardCharsets.UTF_8;

  private boolean allowEmbeddedKey = false;
  private X509Certificate rootCA;
  private MessageDigest nonceDigest;

  // keep 2 maps (1 for sing, 1 for verify) this simplifies the lookups
  private final Map<String, KeyRing> SIGN = new ConcurrentHashMap<>();
  private final Map<String, KeyRing> VERIFY = new ConcurrentHashMap<>();

  /**
   * Adds a JSON Web Key (rfc7517) to the signature maps.
   *
   * @param jwk a JSON Web Key
   * @return self
   */
  public JWT addJWK(JWK jwk) {

    if (jwk.use() == null || "sig".equals(jwk.use())) {
      KeyRing current;
      synchronized (this) {
        if (jwk.mac() != null || jwk.publicKey() != null) {
          current = VERIFY.computeIfAbsent(jwk.getAlgorithm(), k -> new KeyRing());
          addJWK(current, jwk);
        }
        if (jwk.mac() != null || jwk.privateKey() != null) {
          current = SIGN.computeIfAbsent(jwk.getAlgorithm(), k -> new KeyRing());
          addJWK(current, jwk);
        }
      }
    } else {
      LOG.warn("JWK skipped: use: sig != " + jwk.use());
    }

    return this;
  }

  /**
   * Enable/Disable support for embedded keys. Default {@code false}.
   * <p>
   * By default this is disabled as it could be used as an attack vector to the application. A malicious user could
   * generate a self signed certificate and embed the public certificate on the token, which would always pass the
   * validation.
   * <p>
   * Users of this feature should regardless of the validation status, ensure that the chain is valid by adding a
   * well known root certificate (that has been previously agreed with the server).
   *
   * @param allowEmbeddedKey when true embedded keys are used to check the signature.
   * @return fluent self.
   */
  public JWT allowEmbeddedKey(boolean allowEmbeddedKey) {
    this.allowEmbeddedKey = allowEmbeddedKey;
    return this;
  }

  /**
   * Set the root CA certificate for the embedded keys. When handling tokens with embedded keys, certificate chains
   * shall be verified against the provided root CA to ensure a web of trust.
   *
   * @param rootCA base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER [ITU.X690.2008] PKIX
   *               certificate value.
   * @return fluent self.
   */
  public JWT embeddedKeyRootCA(String rootCA) throws CertificateException {
    this.rootCA = JWS.parseX5c(base64Decode(rootCA));
    this.allowEmbeddedKey = true;
    return this;
  }

  public JWT nonceAlgorithm(String alg) {
    if (alg == null) {
      nonceDigest = null;
    } else {
      try {
        nonceDigest = MessageDigest.getInstance(alg);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalArgumentException(e);
      }
    }
    return this;
  }

  private void addJWK(KeyRing keyring, JWK jwk) {
    boolean replaced = false;
    for (int i = 0; i < keyring.size(); i++) {
      if (keyring.get(i).jwk().label().equals(jwk.label())) {
        // replace
        LOG.info("replacing JWK with label " + jwk.label());
        keyring.set(i, new JWS(jwk));
        replaced = true;
        break;
      }
    }

    if (!replaced) {
      // non existent, add it!
      keyring.add(new JWS(jwk));
    }
  }

  public static JsonObject parse(final byte[] token) {
    return parse(new String(token, UTF8));
  }

  public static JsonObject parse(final String token) {
    String[] segments = token.split("\\.");
    if (segments.length < 2 || segments.length > 3) {
      throw new RuntimeException("Not enough or too many segments [" + segments.length + "]");
    }

    // All segment should be base64
    String headerSeg = segments[0];
    String payloadSeg = segments[1];
    String signatureSeg = segments.length == 2 ? null : segments[2];

    // base64 decode and parse JSON
    JsonObject header = new JsonObject(new String(base64UrlDecode(headerSeg), UTF8));
    JsonObject payload = new JsonObject(new String(base64UrlDecode(payloadSeg), UTF8));

    return new JsonObject()
      .put("header", header)
      .put("payload", payload)
      .put("signatureBase", (headerSeg + "." + payloadSeg))
      .put("signature", signatureSeg);
  }

  public JsonObject decode(final String token) throws SignatureException {
    return decode(token, false, null);
  }

  public JsonObject decode(final String token, List<X509CRL> crls) throws SignatureException {
    return decode(token, false, crls);
  }

  public JsonObject decode(final String token, boolean full, List<X509CRL> crls) throws SignatureException {
    // lock the secure state
    String[] segments = token.split("\\.");

    if (segments.length < 2) {
      throw new IllegalArgumentException("Invalid format for JWT");
    }

    // All segment should be base64
    String headerSeg = segments[0];
    String payloadSeg = segments[1];
    String signatureSeg = segments.length == 3 ? segments[2] : null;

    // empty signature is never allowed
    if ("".equals(signatureSeg)) {
      throw new IllegalStateException("Signature is required");
    }

    // base64 decode and parse JSON
    JsonObject header = new JsonObject(Buffer.buffer(base64UrlDecode(headerSeg)));

    final boolean unsecure = isUnsecure();
    if (unsecure) {
      // if there isn't a certificate chain in the header, we are dealing with a strictly
      // unsecure mode validation. In this case the number of segments must be 2
      // if there is a certificate chain, we allow it to proceed and later we will assert
      // against this chain
      if (!allowEmbeddedKey && segments.length != 2) {
        throw new IllegalStateException("JWT is in unsecured mode but token is signed.");
      }
    } else {
      if (!allowEmbeddedKey && segments.length != 3) {
        throw new IllegalStateException("JWT is in secure mode but token is not signed.");
      }
    }

    JsonObject payload = new JsonObject(Buffer.buffer(base64UrlDecode(payloadSeg)));

    String alg = header.getString("alg");

    // if we only allow secure alg, then none is not a valid option
    if (!unsecure && "none".equals(alg)) {
      throw new IllegalStateException("Algorithm \"none\" not allowed");
    }

    // handle the x5c case, only in allowEmbeddedKey mode
    if (allowEmbeddedKey && header.containsKey("x5c")) {
      // if signatureSeg is null fail
      if (signatureSeg == null) {
        throw new SignatureException("missing signature segment");
      }

      try {
        JsonArray chain = header.getJsonArray("x5c");
        List<X509Certificate> certChain = new ArrayList<>();

        if (chain == null || chain.size() == 0) {
          throw new IllegalArgumentException("x5c chain is null or empty");
        }

        for (int i = 0; i < chain.size(); i++) {
          // "x5c" (X.509 Certificate Chain) Header Parameter
          // https://tools.ietf.org/html/rfc7515#section-4.1.6
          // states:
          // Each string in the array is a base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
          // [ITU.X690.2008] PKIX certificate value.
          certChain.add(JWS.parseX5c(base64Decode(chain.getString(i))));
        }

        if (rootCA != null) {
          certChain.add(rootCA);
          CertificateHelper.checkValidity(certChain, true, crls);
        } else {
          CertificateHelper.checkValidity(certChain, false, crls);
        }

        if (JWS.verifySignature(alg, certChain.get(0), base64UrlDecode(signatureSeg), (headerSeg + "." + payloadSeg).getBytes(UTF8))) {
          // ok
          return full ? new JsonObject().put("header", header).put("payload", payload) : payload;
        } else {
          throw new SignatureException("Signature verification failed");
        }
      } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
        throw new SignatureException("Signature verification failed", e);
      }
    }

    // verify signature. `sign` will return base64 string.
    if (!unsecure) {
      KeyRing signatures = VERIFY.get(alg);

      if (signatures == null || signatures.size() == 0) {
        throw new NoSuchKeyIdException(alg);
      }

      // if signatureSeg is null fail
      if (signatureSeg == null) {
        throw new SignatureException("missing signature segment");
      }
      byte[] payloadInput = base64UrlDecode(signatureSeg);
      if (nonceDigest != null && header.containsKey("nonce")) {
        // this is an Azure Graph extension, a nonce is added to the token
        // after the serialization. The original value is the digest of the
        // post value.
        synchronized (this) {
          nonceDigest.reset();
          header.put("nonce", base64UrlEncode(nonceDigest.digest(header.getString("nonce").getBytes(StandardCharsets.UTF_8))));
          headerSeg = base64UrlEncode(header.encode().getBytes(StandardCharsets.UTF_8));
        }
      }
      byte[] signingInput = (headerSeg + "." + payloadSeg).getBytes(UTF8);

      String kid = header.getString("kid");
      boolean hasKey = false;

      for (JWS jws : signatures) {
        // if a token has a kid and it doesn't match the crypto id skip it
        if (kid != null && jws.jwk().getId() != null && !kid.equals(jws.jwk().getId())) {
          continue;
        }
        // signal that this object crypto's list has the required key
        hasKey = true;
        if (jws.verify(payloadInput, signingInput)) {
          return full ? new JsonObject().put("header", header).put("payload", payload) : payload;
        }
      }

      if (hasKey) {
        throw new SignatureException("Signature verification failed");
      } else {
        throw new NoSuchKeyIdException(alg, kid);
      }
    }

    return full ? new JsonObject().put("header", header).put("payload", payload) : payload;
  }

  public String sign(JsonObject payload, JWTOptions options) {
    final boolean unsecure = isUnsecure();
    final String algorithm = options.getAlgorithm();

    // if we only allow secure alg, then none is not a valid option
    if (!unsecure && "none".equals(algorithm)) {
      throw new IllegalStateException("Algorithm \"none\" not allowed");
    }

    final JWS jws;
    final String kid;

    if (!unsecure) {
      KeyRing signatures = SIGN.get(algorithm);

      if (signatures == null || signatures.size() == 0) {
        throw new RuntimeException("Algorithm not supported/allowed: " + algorithm);
      }

      // lock the crypto implementation
      jws = signatures.get();
      kid = jws.jwk().getId();
    } else {
      jws = null;
      kid = null;
    }

    // header, typ is fixed value.
    JsonObject header = new JsonObject()
      .mergeIn(options.getHeader())
      .put("typ", "JWT")
      .put("alg", algorithm);

    // add kid if present
    if (kid != null) {
      header.put("kid", kid);
    }

    // NumericDate is a number is seconds since 1st Jan 1970 in UTC
    long timestamp = System.currentTimeMillis() / 1000;

    if (!options.isNoTimestamp()) {
      payload.put("iat", payload.getValue("iat", timestamp));
    }

    if (options.getExpiresInSeconds() > 0) {
      payload.put("exp", timestamp + options.getExpiresInSeconds());
    }

    if (options.getAudience() != null && options.getAudience().size() >= 1) {
      if (options.getAudience().size() > 1) {
        payload.put("aud", new JsonArray(options.getAudience()));
      } else {
        payload.put("aud", options.getAudience().get(0));
      }
    }

    if (options.getIssuer() != null) {
      payload.put("iss", options.getIssuer());
    }

    if (options.getSubject() != null) {
      payload.put("sub", options.getSubject());
    }

    // create segments, all segment should be base64 string
    String headerSegment = base64UrlEncode(header.encode().getBytes(StandardCharsets.UTF_8));
    String payloadSegment = base64UrlEncode(payload.encode().getBytes(StandardCharsets.UTF_8));

    if (!unsecure) {
      String signingInput = headerSegment + "." + payloadSegment;
      String signSegment = base64UrlEncode(jws.sign(signingInput.getBytes(UTF8)));
      return headerSegment + "." + payloadSegment + "." + signSegment;
    } else {
      return headerSegment + "." + payloadSegment;
    }
  }

  public boolean isUnsecure() {
    return VERIFY.size() == 0 && SIGN.size() == 0;
  }

  public Collection<String> availableAlgorithms() {
    Set<String> algorithms = new HashSet<>();
    // the spec requires none to be always available
    algorithms.add("none");

    algorithms.addAll(VERIFY.keySet());
    algorithms.addAll(SIGN.keySet());

    return algorithms;
  }
}
