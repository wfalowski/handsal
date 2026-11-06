import { db, scopes } from "@handsal/db";
import type { ScopeDto, scopeCreateSchema, scopeUpdateSchema } from "@handsal/shared";
import { and, asc, eq } from "drizzle-orm";
import type { z } from "zod";
import { ApiError } from "../middleware/error-handler.js";
import { assertResource, assertUuid, toScopeDto } from "./resource.service.js";

type AgentPolicy = ScopeDto["agentPolicy"];
export type ScopeCreateInput = z.infer<typeof scopeCreateSchema> & { agentPolicy?: AgentPolicy };
export type ScopeUpdateInput = z.infer<typeof scopeUpdateSchema> & { agentPolicy?: AgentPolicy };

const notFound = () => new ApiError(404, "scope_not_found", "Scope not found");

/** Maps the `(resource_id, name)` unique violation to 409; rethrows anything else. */
function mapNameConflict(err: unknown): never {
  const cause = (err as { cause?: { code?: string; constraint?: string } }).cause;
  if (cause?.code === "23505" && cause.constraint === "uq_scopes_resource_id_name") {
    throw new ApiError(
      409,
      "scope_exists",
      "A scope with this name already exists on the resource",
    );
  }
  throw err;
}

const scopeWhere = (tenantId: string, resourceId: string, scopeId: string) =>
  and(eq(scopes.tenantId, tenantId), eq(scopes.resourceId, resourceId), eq(scopes.id, scopeId));

export async function listScopes(tenantId: string, resourceId: string): Promise<ScopeDto[]> {
  await assertResource(tenantId, resourceId);
  const rows = await db
    .select()
    .from(scopes)
    .where(and(eq(scopes.tenantId, tenantId), eq(scopes.resourceId, resourceId)))
    .orderBy(asc(scopes.name));
  return rows.map(toScopeDto);
}

export async function createScope(
  tenantId: string,
  resourceId: string,
  input: ScopeCreateInput,
): Promise<ScopeDto> {
  await assertResource(tenantId, resourceId);
  const [row] = await db
    .insert(scopes)
    .values({
      tenantId,
      resourceId,
      name: input.name,
      description: input.description ?? null,
      agentPolicy: input.agentPolicy ?? "auto",
    })
    .returning()
    .catch(mapNameConflict);
  return toScopeDto(row);
}

export async function updateScope(
  tenantId: string,
  resourceId: string,
  scopeId: string,
  input: ScopeUpdateInput,
): Promise<ScopeDto> {
  await assertResource(tenantId, resourceId);
  assertUuid(scopeId, notFound);
  const set = { name: input.name, description: input.description, agentPolicy: input.agentPolicy };
  // Drizzle rejects an empty SET; an empty PATCH is a no-op read.
  const [row] = Object.values(set).every((v) => v === undefined)
    ? await db
        .select()
        .from(scopes)
        .where(scopeWhere(tenantId, resourceId, scopeId))
        .limit(1)
    : await db
        .update(scopes)
        .set(set)
        .where(scopeWhere(tenantId, resourceId, scopeId))
        .returning()
        .catch(mapNameConflict);
  if (!row) throw notFound();
  return toScopeDto(row);
}

/** Grants on the scope go with it (FK `on delete cascade`). */
export async function deleteScope(
  tenantId: string,
  resourceId: string,
  scopeId: string,
): Promise<void> {
  await assertResource(tenantId, resourceId);
  assertUuid(scopeId, notFound);
  const deleted = await db
    .delete(scopes)
    .where(scopeWhere(tenantId, resourceId, scopeId))
    .returning({ id: scopes.id });
  if (deleted.length === 0) throw notFound();
}
