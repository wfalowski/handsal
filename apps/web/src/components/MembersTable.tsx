import type { MemberDto, TenantRole } from "@handsal/shared";
import { useState } from "react";
import { initials, relativeTime, tenantTint } from "../lib/format";
import { useMembers, useRemoveMember, useUpdateMemberRole } from "../lib/queries";
import { Button } from "./Button";
import { ConfirmDialog } from "./ConfirmDialog";
import { InviteMemberDialog, ROLE_OPTIONS, selectClass } from "./InviteMemberDialog";
import { Table, Td, Th } from "./Table";
import { useToast } from "./Toast";

type Props = { tenantId: string; canEdit: boolean };

export function MembersTable({ tenantId, canEdit }: Props) {
  const toast = useToast();
  const members = useMembers(tenantId);
  const updateRole = useUpdateMemberRole(tenantId);
  const remove = useRemoveMember(tenantId);
  const [inviting, setInviting] = useState(false);
  const [removing, setRemoving] = useState<MemberDto | null>(null);

  function changeRole(m: MemberDto, role: TenantRole) {
    updateRole.mutate(
      { adminUserId: m.adminUserId, role },
      {
        onSuccess: () => toast.success(`${m.name} is now ${role}`),
        onError: (e) => toast.error(e.message),
      },
    );
  }

  function doRemove() {
    if (!removing) return;
    remove.mutate(removing.adminUserId, {
      onSuccess: () => {
        toast.success(`${removing.name} removed`);
        setRemoving(null);
      },
      onError: (e) => {
        toast.error(e.message);
        setRemoving(null);
      },
    });
  }

  return (
    <div className="flex flex-col gap-4">
      {canEdit && (
        <div className="flex justify-end">
          <Button variant="secondary" size="sm" onClick={() => setInviting(true)}>
            Invite
          </Button>
        </div>
      )}
      <Table minWidth={620}>
        <thead>
          <tr>
            <Th>Member</Th>
            <Th>Last seen</Th>
            <Th>Role</Th>
            {canEdit && (
              <Th>
                <span className="sr-only">Actions</span>
              </Th>
            )}
          </tr>
        </thead>
        <tbody>
          {members.data?.map((m) => {
            const tint = tenantTint(m.email);
            return (
              <tr key={m.adminUserId}>
                <Td>
                  <div className="flex items-center gap-3">
                    <span
                      aria-hidden="true"
                      className="flex h-8 w-8 flex-none items-center justify-center rounded-lg font-semibold text-xs"
                      style={{ background: tint.tint, color: tint.ink }}
                    >
                      {initials(m.name || m.email)}
                    </span>
                    <div className="flex min-w-0 flex-col">
                      <span className="font-medium">{m.name}</span>
                      <span className="truncate text-muted text-xs">{m.email}</span>
                    </div>
                  </div>
                </Td>
                <Td className="whitespace-nowrap text-muted">
                  {m.lastLoginAt ? relativeTime(m.lastLoginAt) : "never"}
                </Td>
                <Td>
                  {canEdit ? (
                    <select
                      aria-label={`Role for ${m.name}`}
                      className={`${selectClass} h-9`}
                      value={m.role}
                      disabled={updateRole.isPending}
                      onChange={(e) => changeRole(m, e.target.value as TenantRole)}
                    >
                      {ROLE_OPTIONS.map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <span className="capitalize">{m.role}</span>
                  )}
                </Td>
                {canEdit && (
                  <Td className="text-right">
                    <Button variant="ghost" size="sm" onClick={() => setRemoving(m)}>
                      Remove
                    </Button>
                  </Td>
                )}
              </tr>
            );
          })}
        </tbody>
      </Table>
      <InviteMemberDialog open={inviting} onClose={() => setInviting(false)} tenantId={tenantId} />
      <ConfirmDialog
        open={removing !== null}
        onClose={() => setRemoving(null)}
        title="Remove member?"
        confirmLabel="Remove"
        danger
        onConfirm={doRemove}
        loading={remove.isPending}
      >
        {removing?.name} ({removing?.email}) will lose access to this tenant.
      </ConfirmDialog>
    </div>
  );
}
