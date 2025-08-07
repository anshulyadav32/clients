import { SystemNotificationEvent } from "@bitwarden/common/platform/notifications/system-notifications.service";
import { UserId } from "@bitwarden/user-core";

export abstract class AuthRequestAnsweringServiceAbstraction {
  abstract receivedPendingAuthRequest(userId: UserId, notificationId: string): Promise<void>;

  abstract handleAuthRequestNotificationClicked(
    event: SystemNotificationEvent,
    authRequestId: string,
  ): Promise<void>;
}
