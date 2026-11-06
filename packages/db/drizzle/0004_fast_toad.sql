CREATE TYPE "public"."delegation_scope_mode" AS ENUM('intersection', 'agent_only');--> statement-breakpoint
ALTER TABLE "applications" ADD COLUMN "may_act_for" text[] DEFAULT '{}'::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "applications" ADD COLUMN "delegation_scope_mode" "delegation_scope_mode" DEFAULT 'intersection' NOT NULL;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "external_idp" jsonb;