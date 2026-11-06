import { SLUG_REGEX } from "@handsal/shared";
import { useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { ApiRequestError } from "../lib/api";
import { slugify } from "../lib/format";
import { useCreateTenant } from "../lib/queries";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { Input } from "./Input";
import { useToast } from "./Toast";

type Props = { open: boolean; onClose: () => void };

export function NewTenantDialog({ open, onClose }: Props) {
  return (
    <Dialog open={open} onClose={onClose} title="New tenant">
      <NewTenantForm onClose={onClose} />
    </Dialog>
  );
}

function NewTenantForm({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const toast = useToast();
  const create = useCreateTenant();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [taken, setTaken] = useState(false);

  const slugError = taken
    ? "This slug is already taken"
    : slug && !SLUG_REGEX.test(slug)
      ? "Use lowercase letters, numbers and hyphens (no leading or trailing hyphen)"
      : undefined;

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    create.mutate(
      { name: name.trim(), slug },
      {
        onSuccess: (tenant) => {
          toast.success(`Tenant ${tenant.name} created`);
          onClose();
          navigate({ to: "/t/$tenantId/applications", params: { tenantId: tenant.id } });
        },
        onError: (err) => {
          if (err instanceof ApiRequestError && err.status === 409) setTaken(true);
          else toast.error(err.message);
        },
      },
    );
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <Input
        label="Name"
        value={name}
        required
        maxLength={255}
        autoComplete="off"
        onChange={(e) => {
          setName(e.target.value);
          if (!slugEdited) setSlug(slugify(e.target.value));
          setTaken(false);
        }}
      />
      <Input
        label="Slug"
        value={slug}
        required
        autoComplete="off"
        className="font-mono"
        hint="Used in the issuer URL: /t/{slug}"
        error={slugError}
        onChange={(e) => {
          setSlug(e.target.value);
          setSlugEdited(true);
          setTaken(false);
        }}
      />
      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button
          type="submit"
          loading={create.isPending}
          disabled={!name.trim() || !!slugError || !slug}
        >
          Create tenant
        </Button>
      </div>
    </form>
  );
}
