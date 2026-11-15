CREATE TYPE "public"."tenant_member_status" AS ENUM('active', 'pending');--> statement-breakpoint
ALTER TABLE "tenant_members" ADD COLUMN "status" "tenant_member_status" DEFAULT 'active' NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_members" ADD COLUMN "invited_by" uuid;--> statement-breakpoint
ALTER TABLE "tenant_members" ADD COLUMN "invited_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "tenant_members" ADD CONSTRAINT "tenant_members_invited_by_admin_users_id_fk" FOREIGN KEY ("invited_by") REFERENCES "public"."admin_users"("id") ON DELETE set null ON UPDATE no action;