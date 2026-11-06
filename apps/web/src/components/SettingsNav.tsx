import clsx from "clsx";

export const SETTINGS_SECTIONS = [
  { id: "general", label: "General" },
  { id: "signing-keys", label: "Signing keys" },
  { id: "token-defaults", label: "Token defaults" },
  { id: "external-idp", label: "External IdP" },
  { id: "approval-webhook", label: "Approvals" },
  { id: "members", label: "Members" },
  { id: "danger", label: "Danger zone" },
] as const;

export type SettingsSection = (typeof SETTINGS_SECTIONS)[number]["id"];

type Props = {
  active?: string;
  showDanger: boolean;
  onSelect: (id: SettingsSection) => void;
};

export function SettingsNav({ active, showDanger, onSelect }: Props) {
  return (
    <nav aria-label="Settings sections" className="sticky top-6 flex flex-col gap-0.5 self-start">
      {SETTINGS_SECTIONS.filter((s) => showDanger || s.id !== "danger").map((s) => (
        <a
          key={s.id}
          href={`#${s.id}`}
          aria-current={active === s.id ? "location" : undefined}
          onClick={(e) => {
            e.preventDefault();
            onSelect(s.id);
          }}
          className={clsx(
            "flex h-[34px] items-center rounded-lg pr-3 pl-3 text-sm",
            active === s.id ? "bg-hover font-medium text-ink" : "text-body hover:bg-hover",
            s.id === "danger" && "text-danger",
          )}
        >
          {s.label}
        </a>
      ))}
    </nav>
  );
}
