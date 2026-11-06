CREATE TYPE "public"."agent_policy" AS ENUM('auto', 'approval', 'never');--> statement-breakpoint
CREATE TYPE "public"."application_kind" AS ENUM('service', 'agent');--> statement-breakpoint
CREATE TYPE "public"."application_status" AS ENUM('active', 'disabled');--> statement-breakpoint
CREATE TYPE "public"."resource_kind" AS ENUM('api', 'mcp');--> statement-breakpoint
CREATE TYPE "public"."resource_status" AS ENUM('active', 'disabled');--> statement-breakpoint
CREATE TYPE "public"."signing_key_status" AS ENUM('active', 'retiring', 'retired');--> statement-breakpoint
CREATE TYPE "public"."tenant_role" AS ENUM('owner', 'admin', 'auditor');--> statement-breakpoint
CREATE TYPE "public"."tenant_status" AS ENUM('active', 'paused');--> statement-breakpoint
CREATE TYPE "public"."token_endpoint_auth_method" AS ENUM('client_secret_basic', 'client_secret_post', 'private_key_jwt');--> statement-breakpoint
CREATE TYPE "public"."token_event_outcome" AS ENUM('issued', 'denied', 'revoked');--> statement-breakpoint
CREATE TABLE "admin_users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar(255) NOT NULL,
	"password_hash" varchar(512) NOT NULL,
	"name" varchar(255) NOT NULL,
	"is_super_admin" boolean DEFAULT false NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "admin_users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "application_grants" (
	"tenant_id" uuid NOT NULL,
	"application_id" uuid NOT NULL,
	"scope_id" uuid NOT NULL,
	CONSTRAINT "application_grants_application_id_scope_id_pk" PRIMARY KEY("application_id","scope_id")
);
--> statement-breakpoint
CREATE TABLE "applications" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"kind" "application_kind" DEFAULT 'service' NOT NULL,
	"client_id" varchar(32) NOT NULL,
	"client_secret_hash" varchar(512),
	"previous_secret_hash" varchar(512),
	"previous_secret_expires_at" timestamp with time zone,
	"secret_rotated_at" timestamp with time zone,
	"token_endpoint_auth_method" "token_endpoint_auth_method" DEFAULT 'client_secret_basic' NOT NULL,
	"token_ttl_seconds" integer,
	"status" "application_status" DEFAULT 'active' NOT NULL,
	"tokens_not_before" timestamp with time zone,
	"last_token_at" timestamp with time zone,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "applications_client_id_unique" UNIQUE("client_id"),
	CONSTRAINT "uq_applications_tenant_id_name" UNIQUE("tenant_id","name"),
	CONSTRAINT "uq_applications_tenant_id_id" UNIQUE("tenant_id","id")
);
--> statement-breakpoint
CREATE TABLE "resources" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"name" varchar(255) NOT NULL,
	"kind" "resource_kind" DEFAULT 'api' NOT NULL,
	"audience" varchar(512) NOT NULL,
	"token_ttl_seconds" integer,
	"status" "resource_status" DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "uq_resources_tenant_id_audience" UNIQUE("tenant_id","audience"),
	CONSTRAINT "uq_resources_tenant_id_name" UNIQUE("tenant_id","name"),
	CONSTRAINT "uq_resources_tenant_id_id" UNIQUE("tenant_id","id")
);
--> statement-breakpoint
CREATE TABLE "revoked_tokens" (
	"jti" varchar(64) PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scopes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"resource_id" uuid NOT NULL,
	"name" varchar(128) NOT NULL,
	"description" text,
	"agent_policy" "agent_policy" DEFAULT 'auto' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "uq_scopes_resource_id_name" UNIQUE("resource_id","name"),
	CONSTRAINT "uq_scopes_tenant_id_id" UNIQUE("tenant_id","id")
);
--> statement-breakpoint
CREATE TABLE "signing_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"kid" varchar(64) NOT NULL,
	"algorithm" varchar(10) DEFAULT 'ES256' NOT NULL,
	"public_key_pem" text NOT NULL,
	"private_key_enc" text NOT NULL,
	"status" "signing_key_status" DEFAULT 'active' NOT NULL,
	"retires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "signing_keys_kid_unique" UNIQUE("kid"),
	CONSTRAINT "uq_signing_keys_tenant_id_id" UNIQUE("tenant_id","id")
);
--> statement-breakpoint
CREATE TABLE "tenant_members" (
	"tenant_id" uuid NOT NULL,
	"admin_user_id" uuid NOT NULL,
	"role" "tenant_role" NOT NULL,
	CONSTRAINT "tenant_members_tenant_id_admin_user_id_pk" PRIMARY KEY("tenant_id","admin_user_id")
);
--> statement-breakpoint
CREATE TABLE "tenants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(255) NOT NULL,
	"slug" varchar(63) NOT NULL,
	"status" "tenant_status" DEFAULT 'active' NOT NULL,
	"default_token_ttl_seconds" integer DEFAULT 3600 NOT NULL,
	"introspection_enabled" boolean DEFAULT true NOT NULL,
	"key_rotation_days" integer,
	"tokens_not_before" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenants_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "token_events" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"application_id" uuid,
	"application_client_id" varchar(32),
	"resource_id" uuid,
	"audience" varchar(512),
	"outcome" "token_event_outcome" NOT NULL,
	"reason" varchar(64),
	"scopes" text[] DEFAULT '{}'::text[] NOT NULL,
	"jti" varchar(64),
	"expires_at" timestamp with time zone,
	"source_ip" varchar(45),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "application_grants" ADD CONSTRAINT "application_grants_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_grants" ADD CONSTRAINT "fk_application_grants_application" FOREIGN KEY ("tenant_id","application_id") REFERENCES "public"."applications"("tenant_id","id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_grants" ADD CONSTRAINT "fk_application_grants_scope" FOREIGN KEY ("tenant_id","scope_id") REFERENCES "public"."scopes"("tenant_id","id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "applications" ADD CONSTRAINT "applications_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "applications" ADD CONSTRAINT "applications_created_by_admin_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."admin_users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "resources" ADD CONSTRAINT "resources_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "revoked_tokens" ADD CONSTRAINT "revoked_tokens_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scopes" ADD CONSTRAINT "scopes_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scopes" ADD CONSTRAINT "fk_scopes_resource" FOREIGN KEY ("tenant_id","resource_id") REFERENCES "public"."resources"("tenant_id","id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "signing_keys" ADD CONSTRAINT "signing_keys_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_members" ADD CONSTRAINT "tenant_members_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_members" ADD CONSTRAINT "tenant_members_admin_user_id_admin_users_id_fk" FOREIGN KEY ("admin_user_id") REFERENCES "public"."admin_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "token_events" ADD CONSTRAINT "token_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_application_grants_scope_id" ON "application_grants" USING btree ("scope_id");--> statement-breakpoint
CREATE INDEX "idx_application_grants_tenant_id" ON "application_grants" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX "idx_applications_tenant_id" ON "applications" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX "idx_revoked_tokens_expires_at" ON "revoked_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_signing_keys_one_active_per_tenant" ON "signing_keys" USING btree ("tenant_id") WHERE "signing_keys"."status" = 'active';--> statement-breakpoint
CREATE INDEX "idx_tenant_members_admin_user_id" ON "tenant_members" USING btree ("admin_user_id");--> statement-breakpoint
CREATE INDEX "idx_token_events_tenant_id_created_at" ON "token_events" USING btree ("tenant_id","created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "idx_token_events_jti" ON "token_events" USING btree ("jti");