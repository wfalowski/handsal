CREATE TYPE "public"."application_key_status" AS ENUM('active', 'retiring');--> statement-breakpoint
CREATE TABLE "application_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"application_id" uuid NOT NULL,
	"kid" varchar(128) NOT NULL,
	"algorithm" varchar(10) DEFAULT 'ES256' NOT NULL,
	"public_key_pem" text NOT NULL,
	"fingerprint_sha256" varchar(64) NOT NULL,
	"status" "application_key_status" DEFAULT 'active' NOT NULL,
	"retires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "uq_application_keys_application_id_kid" UNIQUE("application_id","kid"),
	CONSTRAINT "uq_application_keys_application_id_fingerprint" UNIQUE("application_id","fingerprint_sha256")
);
--> statement-breakpoint
ALTER TABLE "applications" ADD COLUMN "agent_runtime" varchar(64);--> statement-breakpoint
ALTER TABLE "applications" ADD COLUMN "operator_email" varchar(255);--> statement-breakpoint
ALTER TABLE "applications" ADD COLUMN "allowed_cidrs" text[] DEFAULT '{}'::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "applications" ADD COLUMN "max_scopes_per_token" integer;--> statement-breakpoint
ALTER TABLE "applications" ADD COLUMN "token_budget_per_hour" integer;--> statement-breakpoint
ALTER TABLE "token_events" ADD COLUMN "task_id" varchar(128);--> statement-breakpoint
ALTER TABLE "token_events" ADD COLUMN "actor_sub" varchar(255);--> statement-breakpoint
ALTER TABLE "application_keys" ADD CONSTRAINT "application_keys_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_keys" ADD CONSTRAINT "fk_application_keys_application" FOREIGN KEY ("tenant_id","application_id") REFERENCES "public"."applications"("tenant_id","id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_application_keys_application_id" ON "application_keys" USING btree ("application_id");--> statement-breakpoint
CREATE INDEX "idx_token_events_application_id_created_at" ON "token_events" USING btree ("application_id","created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "idx_token_events_task_id" ON "token_events" USING btree ("task_id");