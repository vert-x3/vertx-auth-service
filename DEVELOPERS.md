# Vert.x Auth from 10k ft

Vert.x Auth is a set of modules that provide authentication and authorization support for Vert.x applications.

There are 4 kinds of authentication that Vert.x Auth supports:

* username password authentication - `htdigest`, `htpassword`, `ldap`, `properties`, `sql-client`
* token based authentication - `jwt`, `oauth2`
* passwordless - `webauthn`
* one time password - `totp` / `hotp`

There are 3 kinds of authorization that Vert.x Auth supports:

* properties - `properties`
* sql based - `sql-client`
* token based - `jwt`, `oauth2`

## Authentication

Authentication is the process of verifying the user is who they claim they are. This is done by providing some form of
credentials to the authentication provider. The authentication provider then verifies the credentials and returns a
`User` object if the credentials are valid.

In the common module you will find the following interfaces:

* `TokenCredentials`
* `UsernamePasswordCredentials`

As they can be used across multiple modules, for specific ones you will find the following interfaces:

* `WebauthnCredentials`
* `OtpCredentials`
* `HtdigestCredentials`

Credentials are just data objects that contain the credentials to be verified. The `User` object is a representation of
the authenticated user (after the credential check) in a way the API is just exchanging `Credentials` for `User`
objects.

### Username Password Authentication

In this case vert.x adopts the `P-H-C` standard for storing passwords. The `P-H-C` standard is a standard for storing
passwords that is designed to be secure and flexible. It is a standard that is used by many other systems and
frameworks.

https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md

For hashing we need algorithms. Vert.x doesn't implement any of the algorithms or rely on 3rd party libraries. All
functions come from the JDK or can be added using a service loader interface `HashingAlgorithm`.

You can see the service loader interface in action for `htpassword` where `crypt` from Apache can be added as an
optional dependency.

### Token Based Authentication

Token based authentication is a way to authenticate a user by providing a token. The token is usually provided in the
form of a JWT. Vert.x has a JOSE (JSON Object Signing and Encryption) implementation that can be used to create and
validate tokens. The JOSE code predates the first release of JOSE4J and like the rest, only depends on the JDK itself.

Encryption is actually not fully implemented, mostly because it is feature that never got much adoption and is not
needed for the vert.x use cases.

* JWT - Performs verifications and generation of tokens, it follows the RFCs for JWT and JWS and has a special quirk
  for the `nonce` algorithm used by Azure AD v1 (the default format for enterprise Azure AD deployments, the expensive)
  deployments, not the trial/cheap stuff most people do.
* JWK - Loads keys in JWKs format and can be used to verify tokens. It can read RSA, EC or EdDSA keys (you may need
  specific JDK versions to have those algorithms available, EC requires 11, EdDSA requires 15).
* JWS - Performs verifications and generation of JWS. It can deal with certificates and CRLs.
* JWE - Encryption - Almost not used, but it is there if you need it.

All code is imperative, as there is no need to perform IO, it is all in memory.

### Passwordless

Passwordless authentication is a way to authenticate a user by providing a `webauth` message. Webauthn is a standard for
a decentralized authentication protocol that is based on public key cryptography. It is a standard that is used by many
other systems and frameworks and is supported by all major browsers. Microsoft, Apple and Google have all adopted it.

Vert.x webauthn passed the `TCK` (Test Compatibility Kit) and is fully compliant with the standard. It was also publicly
available before `webauthn4j`.

Webauthn relies on JWT for many operations, but because it can run on low resources devices, it has a special encoding:
`CBOR` hence the `cose` package. It relies on the `jose` code but uses `CBOR` instead of `JSON`.

Webauthn uses Certificates (specially Apple does), gives that we need to extract validation from the certificate itself
the common package has a simple `ASN1` class to parse sections from a java `X509Certificate`. We only parse, we don't
generate. Also there is a `CertificateHelper` that can be used to verify certificate chains and CRLs. The reason to
avoid the JDK implementation this time, is because the JDK implementation performs blocking network IO to fetch CRLs
and this would not work with the asynchronous event loop. Instead the helper, expects the CRLs to be loaded in memory
and the check is quick.

### One Time Password

This is a simple module that provides support for one time passwords. It supports both `totp` and `hotp` and can be
configured to use a `clock` or `counter` based algorithm. Google authenticator is usually used as `topt` (Time based).

## Authorization

Vert.x authorization model is more advanced that Quarkus. It is a hybrid between RBAC and ABAC.

While RBAC is a model where you have roles and permissions, ABAC is a model where you have policies and rules.

Vert.x knows:

* `roles` - A role is a group of permissions. A user can have multiple roles.
* `permissions` - A permission is a string that represents an action that can be performed. A role can have multiple
  permissions.
* `wildcard permission` - Can be seen as a simple policy where rules are computed at runtime, like matching with
  wildcards or resources. Rules can include variables that are computed at runtime.

Roles and Permissions can have a optional `resource`. A resource is a opaque string that can be used to limit the the
permission to something the developer defined. Resources can be plain strings like:

* `foo`
* `/usr/local/bin`
* `https://vertx.io`

Or can contain a variable that is computed at runtime during the check:

* `foo/{user}`
* `/usr/{local}/{bin}/{cmd}`

There is no support for wildcards in resources.

Vert.x will get a `Policy` (ABAC) interface (we're working with the community to implement this). A policy can be seen
as a reverse of a RBAC store. Instead of having explicit roles and permissions assigned to a user, you have a collection
of policies  that are matched against a user and if the requirements are valid, the policy permissions are assiged to
that user.

By default, Vert.x will always assume deny, so if you don't have any rules, the user will not be authorized. This is by
design and choice as it ensures that misconfigured application are never exposed incorrectly to the world and
information is secure.

Checking for a match is process:

1. Supply the user authorizations from a provider to `User.authorizations()` (mix and match is allowed, JWT user can
   read authorizations from a SQL database, the token itself or any other module)
2. Create a `AuthorizationContext` for a existing user
3. Supply variables that can be evaluated
4. Given a `Permission` perform a `match` on that context

A boolean result is the outcome.

Authorizations can be simple:

* Permission
* Role
* WildcardPermission

Or logical combinations:

* AndAuthorization
* OrAuthorization
* NotAuthorization

A note on ABAC, the `Policy` will not allow logical combinators, it will only allow a single rule. The reason is that
matching for authorizations is done as an iterative process.

## Authorization Providers

### htdigest

The `htdigest` provider is a simple provider that reads a `.htdigest` file and provides usernames/hashes of passwords.

This provider only support `Authentication`. The provider requires the use of `HtdigestCredentials` as input because
the htdigest spec requires many HTTP specific fields to be provided to attest the user.

### htpasswd

The `htpasswd` provider is a simple provider that reads a `.htpasswd` file and provides usernames/hashes of passwords.

This is one of the simplest providers and only supports `Authentication`. It is a good choice for simple applications.

It supports any algorithm that is supported by the JDK, but also supports the following algorithms:

* APR1
* Crypt
* SHA1 (Apache)

In this case, will require an optional dependency on `apache-commons-codec` to use those algorithms.

Currently there is no support for `bcrypt` and `scrypt` but it can be added as an optional dependency because the
hashing algorithms are provided through a java service loader `HashingAlgorithm` interface.

### jwt

The `jwt` provider is a simple provider that reads a `JWT` token and provides the claims as authorizations. The provider
can do `Authentication` by asserting the signature of the token as proof of authenticity and `Authorization` by reading
a custom claim or claims as the authorizations.

The provider can also generate tokens if private keys are available or if the token is signed with a HMAC algorithm.

### ldap

The `ldap` provider is a simple provider that authenticates a user to a `LDAP` server. This implementation is blocking
and relies on the `javax.naming` package.

### oauth2

Oauth2 is a complex protocol that is used to authenticate users and authorize them. It is a very common protocol and
is used by many systems. This provider does both Oauth2 and OpenId Connect.

Oauth2 is a HTTP protocol that authorizes a user. A user that need to be authn/authz will be redirected to an external
server (Identity Provider) where authentication takes place and the user is redirected back to the application.

There are several ways authentication can take place:

* `Authorization Code` - The most secure way, the user is redirected to the identity provider and the user is
  authenticated. The identity provider will redirect the user back to the application with a `code` that can be
  exchanged for a `token`. The `token` is used to authenticate the user and authorize the user.
* `Resource Owner Password Credentials` - The user is redirected to the identity provider and the user is authenticated.
  The identity provider will redirect the user back to the application with a `token` that can be used to authenticate
  the user and authorize the user.
* `Client Credentials` - The user is redirected to the identity provider and the user is authenticated. The identity
  provider will redirect the user back to the application with a `token` that can be used to authenticate the user and
  authorize the user.
* `Implicit` - Not supported as this is a Client mode, that has to be implemented. Initially this handler was used
  server side only.
* `urn:ietf:params:oauth:grant-type:jwt-bearer` - This is for Service to Service authentication/authorization. The user
  will exchange the current token, for a second bearer token. This allows a user to perform an action "on behalf of" a
  second user or service. Currently we have 2 variations of this to allow Google and Azure quirks to work.

### otp

This provider is a simple provider that reads a `totp` or `hotp` token and verifies the token. The provider can generate
the required url to be registered with a `totp` or `hotp` application (Google Authentication). But it will not generate
a QR code as that would require a dependency on a QR code library and/or java AWT/Swing libraries. Instead one can use
the `qrcode` string and pass it to a library of choice (or render at the client side with JavaScript only).

### properties

The `properties` provider is a simple provider that reads a `.properties` file and provides usernames, passwords and
roles. The format of this file is similar to Apache Shiro for historical reasons:

```
username=password,role1,role2
role1=permission1,permission2
role2=permission3
```

The provider implements both Authentication and Authorization.

### sql-client

The `sql` provider is a simple provider that reads a SQL database and provides usernames, passwords and roles. The
functionality is similar to properties but the data is stored in a SQL database.

### webauthn

The `webauthn` provider is a simple provider that handles the passwordless standard webauthn. The provider can work
without attestation (meaning, trust any registred device) or with attestation (meaning, only trust devices that are
valid). To verify the attestation, more checks are performed at registration time to ensure that non rooted devices
are used for example. The provider implements all attestation protocols as a service loader, if in the future new modes
are added to the spec, either an external jar can provide the implementation of the attestation process or be added
directly to the code base `io.vertx.ext.auth.webauthn.impl.attestation.Attestation`.

The provider implements both Authentication and Authorization. And also support Metadata Service for attestation. This
is a public service that extends the attestation to verify against revoked devices or groups of devices/root
certificates.
