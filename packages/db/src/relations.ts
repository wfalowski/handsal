import { relations } from "drizzle-orm";
import { adminUsers } from "./schema/admin-users.js";
import { applicationGrants } from "./schema/application-grants.js";
import { applications } from "./schema/applications.js";
import { resources } from "./schema/resources.js";
import { revokedTokens } from "./schema/revoked-tokens.js";
import { scopes } from "./schema/scopes.js";
import { signingKeys } from "./schema/signing-keys.js";
import { tenantMembers } from "./schema/tenant-members.js";
import { tenants } from "./schema/tenants.js";
import { tokenEvents } from "./schema/token-events.js";

export const tenantsRelations = relations(tenants, ({ many }) => ({
  members: many(tenantMembers),
  applications: many(applications),
  resources: many(resources),
  scopes: many(scopes),
  signingKeys: many(signingKeys),
  revokedTokens: many(revokedTokens),
  tokenEvents: many(tokenEvents),
}));

export const adminUsersRelations = relations(adminUsers, ({ many }) => ({
  memberships: many(tenantMembers),
}));

export const tenantMembersRelations = relations(tenantMembers, ({ one }) => ({
  tenant: one(tenants, {
    fields: [tenantMembers.tenantId],
    references: [tenants.id],
  }),
  adminUser: one(adminUsers, {
    fields: [tenantMembers.adminUserId],
    references: [adminUsers.id],
  }),
}));

export const applicationsRelations = relations(applications, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [applications.tenantId],
    references: [tenants.id],
  }),
  creator: one(adminUsers, {
    fields: [applications.createdBy],
    references: [adminUsers.id],
  }),
  grants: many(applicationGrants),
}));

export const resourcesRelations = relations(resources, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [resources.tenantId],
    references: [tenants.id],
  }),
  scopes: many(scopes),
}));

export const scopesRelations = relations(scopes, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [scopes.tenantId],
    references: [tenants.id],
  }),
  resource: one(resources, {
    fields: [scopes.resourceId],
    references: [resources.id],
  }),
  grants: many(applicationGrants),
}));

export const applicationGrantsRelations = relations(applicationGrants, ({ one }) => ({
  application: one(applications, {
    fields: [applicationGrants.applicationId],
    references: [applications.id],
  }),
  scope: one(scopes, {
    fields: [applicationGrants.scopeId],
    references: [scopes.id],
  }),
}));

export const signingKeysRelations = relations(signingKeys, ({ one }) => ({
  tenant: one(tenants, {
    fields: [signingKeys.tenantId],
    references: [tenants.id],
  }),
}));

export const revokedTokensRelations = relations(revokedTokens, ({ one }) => ({
  tenant: one(tenants, {
    fields: [revokedTokens.tenantId],
    references: [tenants.id],
  }),
}));

export const tokenEventsRelations = relations(tokenEvents, ({ one }) => ({
  tenant: one(tenants, {
    fields: [tokenEvents.tenantId],
    references: [tenants.id],
  }),
}));
