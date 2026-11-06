CREATE TYPE "public"."approval_rule_action" AS ENUM('auto_approve');--> statement-breakpoint
CREATE TABLE "approval_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"scope_id" uuid NOT NULL,
	"condition" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"action" "approval_rule_action" DEFAULT 'auto_approve' NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "approval_requests" ADD COLUMN "decided_by_rule_id" uuid;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "approval_webhook_url" varchar(2048);--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "approval_webhook_secret_enc" text;--> statement-breakpoint
ALTER TABLE "approval_rules" ADD CONSTRAINT "approval_rules_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approval_rules" ADD CONSTRAINT "approval_rules_created_by_admin_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."admin_users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approval_rules" ADD CONSTRAINT "fk_approval_rules_scope" FOREIGN KEY ("tenant_id","scope_id") REFERENCES "public"."scopes"("tenant_id","id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_approval_rules_tenant_scope" ON "approval_rules" USING btree ("tenant_id","scope_id");--> statement-breakpoint
ALTER TABLE "approval_requests" ADD CONSTRAINT "approval_requests_decided_by_rule_id_approval_rules_id_fk" FOREIGN KEY ("decided_by_rule_id") REFERENCES "public"."approval_rules"("id") ON DELETE set null ON UPDATE no action;