import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
// This import has been flagged as unallowed for this class. It may be involved in a circular dependency loop.
// eslint-disable-next-line no-restricted-imports
import { KeyService } from "@bitwarden/key-management";

import { EncryptService } from "../../key-management/crypto/abstractions/encrypt.service";

export class ContainerService {
  constructor(
    private keyService: KeyService,
    private encryptService: EncryptService,
    private accountService?: AccountService,
  ) {}

  attachToGlobal(global: any) {
    if (!global.bitwardenContainerService) {
      global.bitwardenContainerService = this;
    }
  }

  /**
   * @throws Will throw if KeyService was not instantiated and provided to the ContainerService constructor
   */
  getKeyService(): KeyService {
    if (this.keyService == null) {
      throw new Error("ContainerService.keyService not initialized.");
    }
    return this.keyService;
  }

  /**
   * @throws Will throw if EncryptService was not instantiated and provided to the ContainerService constructor
   */
  getEncryptService(): EncryptService {
    if (this.encryptService == null) {
      throw new Error("ContainerService.encryptService not initialized.");
    }
    return this.encryptService;
  }

  getAccountService(): AccountService {
    if (this.accountService == null) {
      throw new Error("ContainerService.accountService not initialized.");
    }
    return this.accountService;
  }
}
