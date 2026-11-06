import type { z } from "zod";
import type { applicationDtoSchema } from "../validation/application.schema.js";
import type { memberDtoSchema, signingKeyDtoSchema } from "../validation/member.schema.js";
import type { resourceDtoSchema } from "../validation/resource.schema.js";
import type { scopeDtoSchema } from "../validation/scope.schema.js";
import type { tenantDtoSchema } from "../validation/tenant.schema.js";
import type {
  tokenEventDtoSchema,
  tokenStatsDtoSchema,
} from "../validation/token-events.schema.js";

export interface ApiError {
  error: string;
  error_description: string;
  details?: unknown;
}

export type TenantDto = z.infer<typeof tenantDtoSchema>;
export type ApplicationDto = z.infer<typeof applicationDtoSchema>;
export type ResourceDto = z.infer<typeof resourceDtoSchema>;
export type ScopeDto = z.infer<typeof scopeDtoSchema>;
export type SigningKeyDto = z.infer<typeof signingKeyDtoSchema>;
export type MemberDto = z.infer<typeof memberDtoSchema>;
export type TokenEventDto = z.infer<typeof tokenEventDtoSchema>;
export type TokenStatsDto = z.infer<typeof tokenStatsDtoSchema>;
