import { Injectable } from "@angular/core";
import { from, Observable } from "rxjs";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { OrganizationId } from "@bitwarden/common/types/guid";

import {
  GetRiskInsightsReportResponse,
  SaveRiskInsightsReportRequest,
  SaveRiskInsightsReportResponse,
} from "../models/api-models.types";

@Injectable()
export class RiskInsightsApiService {
  constructor(private apiService: ApiService) {}

  saveRiskInsightsReport$(
    request: SaveRiskInsightsReportRequest,
  ): Observable<SaveRiskInsightsReportResponse> {
    const dbResponse = this.apiService.send(
      "POST",
      `/reports/organization-reports`,
      request.data,
      true,
      true,
    );

    return from(dbResponse as Promise<SaveRiskInsightsReportResponse>);
  }

  getRiskInsightsReport$(orgId: OrganizationId): Observable<GetRiskInsightsReportResponse | null> {
    const dbResponse = this.apiService
      .send("GET", `/reports/organization-reports/latest/${orgId.toString()}`, null, true, true)
      .catch((error: any): any => {
        if (error.statusCode === 404) {
          return null; // Handle 404 by returning null or an appropriate default value
        }
        throw error; // Re-throw other errors
      });

    return from(dbResponse as Promise<GetRiskInsightsReportResponse>);
  }
}
