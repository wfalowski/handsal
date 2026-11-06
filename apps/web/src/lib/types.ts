import type { TenantDto, TenantRole } from "@handsal/shared";

export type MeUser = {
  id: string | null;
  email: string | null;
  name: string;
  isSuperAdmin: boolean;
};

export type MeTenant = { id: string; name: string; slug: string; role: TenantRole };

export type MeResponse = { user: MeUser; tenants: MeTenant[] };

export type TenantListItem = TenantDto & {
  appCount: number;
  resourceCount: number;
  tokens24h: number;
};
