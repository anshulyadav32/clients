import { Observable } from "rxjs";

import { SendHashedPassword } from "../../../key-management/sends/send-password.service";
import { SendAccessToken } from "../models/send-access-token";
import {
  GetSendAcccessTokenError,
  TryGetSendAccessTokenError,
} from "../services/send-token.service";

export type SendPasswordCredentials = {
  type: "password";
  passwordHash: SendHashedPassword;
};

// Credentials for sending an OTP to the user's email address.
// This is used when the send requires email verification with an OTP.
export type SendEmailCredentials = {
  type: "email";
  email: string;
};

// Credentials for getting a send access token using an email and OTP.
export type SendEmailOtpCredentials = {
  type: "email-otp";
  email: string;
  otp: string;
};
export type SendAccessCredentials =
  | SendPasswordCredentials
  | SendEmailCredentials
  | SendEmailOtpCredentials;

export abstract class SendTokenService {
  /**
   * Attempts to retrieve a SendAccessToken for the given sendId.
   * If the access token is found in session storage and is not expired, then it returns the token.
   * If the access token is expired, then it returns a SendTokenRetrievalError expired error.
   * If an access token is not found in storage, then it attempts to retrieve it from the server (will succeed for sends that don't require any credentials to view).
   * If the access token is successfully retrieved from the server, then it stores the token in session storage and returns it.
   * If an access token cannot be granted b/c the send requires credentials, then it returns a SendTokenRetrievalError indicating which credentials are required.
   * Any submissions of credentials will be handled by the getSendAccessTokenWithCredentials method.
   * @param sendId The ID of the send to retrieve the access token for.
   * @returns An observable that emits a SendAccessToken if successful, or a TryGetSendAccessTokenError if not.
   */
  abstract tryGetSendAccessToken$: (
    sendId: string,
  ) => Observable<SendAccessToken | TryGetSendAccessTokenError>;

  /**
   * Retrieves a SendAccessToken for the given sendId using the provided credentials.
   * If the access token is successfully retrieved from the server, it stores the token in session storage and returns it.
   * If the access token cannot be granted due to invalid credentials, it returns a GetSendAcccessTokenError.
   * @param sendId The ID of the send to retrieve the access token for.
   * @param sendAccessCredentials The credentials to use for accessing the send.
   * @returns An observable that emits a SendAccessToken if successful, or a GetSendAcccessTokenError if not.
   */
  abstract getSendAccessToken$: (
    sendId: string,
    sendAccessCredentials: SendAccessCredentials,
  ) => Observable<SendAccessToken | GetSendAcccessTokenError>;

  /**
   * Hashes a password for send access.
   * @param password The raw password string to hash.
   * @param keyMaterialUrlB64 The base64 URL encoded key material string.
   * @returns A promise that resolves to the hashed password as a SendHashedPassword.
   */
  abstract hashPassword: (
    password: string,
    keyMaterialUrlB64: string,
  ) => Promise<SendHashedPassword>;
}
