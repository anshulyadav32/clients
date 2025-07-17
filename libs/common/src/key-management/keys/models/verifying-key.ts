import { SdkLoadService } from "@bitwarden/common/platform/abstractions/sdk/sdk-load.service";
import { Utils } from "@bitwarden/common/platform/misc/utils";
import { PureCrypto } from "@bitwarden/sdk-internal";

import { SigningKeyType as SigningKeyAlgorithm } from "../../enums/signing-key-type.enum";

/**
 * A verifying key is a public key used to verify signatures
 */
export class VerifyingKey {
  private innerKey: string;

  constructor(verifyingKey: string) {
    this.innerKey = verifyingKey;
  }

  /**
   * Returns the verifying key in base64 format.
   */
  toString(): string {
    return this.innerKey;
  }

  /**
   * Returns the algorithm of the underlying signature scheme of the verifying key.
   * @throws A decoding error if the key is not a valid Cose-encoded public signature key.
   * @throws A unsupported value error if the key is a valid Cose-encode signature key, but the algorithm is not supported.
   */
  async algorithm(): Promise<SigningKeyAlgorithm> {
    await SdkLoadService.Ready;
    return PureCrypto.key_algorithm_for_verifying_key(Utils.fromB64ToArray(this.innerKey));
  }
}
