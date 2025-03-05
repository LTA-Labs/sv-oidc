# OIDC Service with ZKP Authentication

This is a skeleton implementation of an OpenID Connect (OIDC) service with image-based Zero-Knowledge Proof (ZKP) authentication.

## Features

- **Core OIDC Endpoints**:
  - `/authorize`: Handles the initial authentication request
  - `/token`: Issues access tokens, ID tokens, and refresh tokens
  - `/userinfo`: Provides user claims to clients
  - `/.well-known/jwks.json`: Provides public keys for token verification
  - `/.well-known/openid-configuration`: Provides OIDC metadata

- **Custom Authentication Endpoints**:
  - `/auth/register`: Handles user registration, including ZKP commitment generation
  - `/auth/challenge`: Generates a challenge for authentication
  - `/auth/authenticate`: Executes the challenge-response protocol for login
  - `/auth/logout`: Invalidates sessions and revokes tokens
  - `/introspect`: Allows clients to validate and inspect tokens
  - `/revoke`: Allows clients to explicitly revoke tokens

- **Session Management**:
  - Short-lived access tokens (15 minutes)
  - Longer-lived refresh tokens (7 days)
  - Token revocation and session invalidation

- **Image-Based Authentication**:
  - Users register by generating a ZKP commitment from their chosen image
  - During authentication, users compute a challenge response locally and send it to the backend for validation

## Authentication Flow

### Registration

1. User provides a username and uploads an image
2. Frontend processes the image locally to generate a ZKP commitment
3. Backend stores the ZKP commitment in MongoDB

### Authentication

1. User provides their username
2. Backend generates a random challenge and sends it to the frontend
3. Frontend computes a challenge response using the image and sends it back
4. Backend validates the response against the stored ZKP commitment
5. If successful, the backend issues access and refresh tokens

## Security Considerations

- Sensitive data is encrypted at rest
- Rate limiting is implemented to prevent brute-force attacks
- Tokens have appropriate expiration times
- ZKP ensures that the actual image is never transmitted or stored

## ZKP Implementation Notes

This skeleton includes placeholder functions for ZKP commitment operations. In a real implementation, you would need to:

1. Implement a proper ZKP scheme for image-based authentication
2. Implement secure challenge-response validation