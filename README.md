# Security Library

> 18 April 2020: This project was originally created for [Submersive](https://github.com/submersive). I've migrated the
> codebase from Bitbucket, where Bitbucket Pipelines was used for continuous delivery.

Our security library is tasked with establishing the base security setup for our API services.

The security library builds on Spring Security and is designed with Spring Boot in mind. It is auto-configurable
and the project artifact simply needs to be added to a Spring Boot application's classpath to become activated.

## Authentication

The security library's purpose is to secure HTTP endpoints and authenticate incoming requests.

Spring Actuator HTTP endpoints are unrestricted by default, and all other HTTP endpoints will require the `ROLE_USER`
or `ROLE_ANONYMOUS` authorities to be granted to the authenticated principal.

There are two authentication filters at play:

### PreAuthenticatedAuthenticationFilter

This filter looks in the `Authorization` HTTP header for a pre-authenticated access token in the request.
The access token is expected to be structured as a Json Web Token (JWT) and signed using a HMAC-SHA512 algorithm.

When the access token is verified and found to be valid, the request is authenticated and the `ROLE_USER` authority is
granted on the authenticated principal.

If the access token is found to be invalid, the request is rejected, and an error is returned.

When authenticated through the `PreAuthenticatedAuthenticationFilter`, the principal's username is set to the
user's identifier, allowing for limited access control features.

### AnonymousAuthenticationFilter

This filter is triggered after the `PreAuthenticatedAuthenticationFilter` when an access token is not provided in the
request. The function of this filter is to anonymously authenticate the request, so that all requests to our services
are authenticated on some level.

The `ROLE_ANONYMOUS` authority is granted to all anonymous requests.

When authenticated through the `AnonymousAuthenticationFilter`, the principal's username is a random UUID.

## Configuration

The security library provides some configuration for Spring Boot applications.
Let's walk through the various settings.

    submersive.security:
      enabled: true

You can disable our security library and the underlying Spring Security setup by setting this value to false. A
configuration setting is not required to enable the security library, as it is enabled by default.

    submersive.security:
      token:
        clientKey: submersive
        issuer: submersive.com
        secret: ${JWT_SECRET}

All Spring Boot applications will need to configure the security token to properly verify the incoming access tokens,
as well as issue just-in-time anonymous tokens.

The value of `clientKey` is largely irrelevant and a simple setting of `submersive` will suffice. This value is required
to authorise and validate anonymous tokens.

Incoming access tokens are verified for their issuer and secret. These values must match the `identity-service`, where
access tokens are issued.
