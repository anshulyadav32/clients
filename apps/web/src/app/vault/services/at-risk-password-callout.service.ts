import { Injectable } from "@angular/core";
import { combineLatest, map, Observable } from "rxjs";

import {
  StateProvider,
  UserKeyDefinition,
  VAULT_AT_RISK_PASSWORDS_DISK,
} from "@bitwarden/common/platform/state";
import { UserId } from "@bitwarden/common/types/guid";
import { CipherService } from "@bitwarden/common/vault/abstractions/cipher.service";
import { SecurityTask, SecurityTaskType, TaskService } from "@bitwarden/common/vault/tasks";

export type AtRiskPasswordCalloutData = {
  hadPendingTasks: boolean;
  showTasksCompleteBanner: boolean;
  tasksBannerDismissed: boolean;
};

const AT_RISK_PASSWORD_CALLOUT_KEY = new UserKeyDefinition<AtRiskPasswordCalloutData>(
  VAULT_AT_RISK_PASSWORDS_DISK,
  "atRiskPasswords",
  {
    deserializer: (jsonData) => jsonData,
    clearOn: ["logout", "lock"],
  },
);

@Injectable()
export class AtRiskPasswordCalloutService {
  constructor(
    private taskService: TaskService,
    private cipherService: CipherService,
    private stateProvider: StateProvider,
  ) {}

  pendingTasks$(userId: UserId): Observable<SecurityTask[]> {
    return combineLatest([
      this.taskService.pendingTasks$(userId),
      this.cipherService.cipherViews$(userId),
    ]).pipe(
      map(([tasks, ciphers]) =>
        tasks.filter((t: SecurityTask) => {
          const associatedCipher = ciphers.find((c) => c.id === t.cipherId);

          return (
            t.type === SecurityTaskType.UpdateAtRiskCredential &&
            associatedCipher &&
            !associatedCipher.isDeleted
          );
        }),
      ),
    );
  }

  atRiskPasswordState(userId: UserId) {
    return this.stateProvider.getUser(userId, AT_RISK_PASSWORD_CALLOUT_KEY);
  }

  updateAtRiskPasswordState(userId: UserId, updatedState: AtRiskPasswordCalloutData): void {
    void this.atRiskPasswordState(userId).update(() => updatedState);
  }
}
