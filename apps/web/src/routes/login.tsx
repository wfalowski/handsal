import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { InstanceMark } from "../components/InstanceMark";
import { Logo } from "../components/Logo";
import { ApiRequestError } from "../lib/api";
import { useLogin } from "../lib/queries";

export const Route = createFileRoute("/login")({
  component: LoginPage,
});

const KEY = "text-[#8DA2FB]";

function LoginPage() {
  const navigate = useNavigate();
  const login = useLogin();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    login.mutate({ email, password }, { onSuccess: () => navigate({ to: "/tenants" }) });
  }

  const error =
    login.error instanceof ApiRequestError && login.error.status === 401
      ? "Invalid email or password"
      : login.error?.message;

  return (
    <div className="flex min-h-screen bg-white text-ink">
      <section className="hidden min-w-0 flex-1 basis-1/2 flex-col justify-between gap-12 bg-[#0B0B0F] p-12 text-[#E7E7EA] md:flex">
        <div className="flex items-center gap-2.5">
          <Logo size={28} />
          <InstanceMark nameClassName="text-lg tracking-tight" />
        </div>

        <div className="flex max-w-[560px] flex-col gap-7">
          <h1 className="font-display font-semibold text-[40px] text-white leading-[1.1] tracking-tight">
            Secure authentication between your services.
          </h1>
          <p className="max-w-[460px] text-base text-faint">
            Client credentials, scoped resources and short-lived tokens — a handshake your
            microservices and AI agents can trust.
          </p>

          <div
            aria-hidden="true"
            className="overflow-x-auto rounded-xl border border-[#26262E] bg-[#131318] pt-5 pr-[22px] pb-5 pl-[22px] font-mono text-[13px] text-line-strong leading-[1.7]"
          >
            <div className="mb-3 flex items-center gap-2 text-[#71717A] text-xs">
              <span className="inline-block h-2 w-2 rounded-full bg-[#22C55E]" />
              <span>POST /t/{"{tenant}"}/oauth/token</span>
            </div>
            <div>
              <span className={KEY}>grant_type</span>=client_credentials
            </div>
            <div>
              <span className={KEY}>client_id</span>=app_7f3a9c2e41b8d05k6m1q
            </div>
            <div>
              <span className={KEY}>resource</span>=https://api.billing.example
            </div>
            <div>
              <span className={KEY}>scope</span>=payments:read invoices:write
            </div>
            <div className="my-3.5 h-px bg-[#26262E]" />
            <div className="text-[#71717A]">{"// 200 OK"}</div>
            <div>
              {"{ "}
              <span className={KEY}>"access_token"</span>:{" "}
              <span className="text-[#86EFAC]">"eyJhbGciOiJFUzI1NiIs…"</span>,
            </div>
            <div>
              &nbsp;&nbsp;<span className={KEY}>"token_type"</span>:{" "}
              <span className="text-[#86EFAC]">"Bearer"</span>,
            </div>
            <div>
              &nbsp;&nbsp;<span className={KEY}>"expires_in"</span>:{" "}
              <span className="text-[#FCD34D]">3600</span> {"}"}
            </div>
          </div>
        </div>

        <p className="text-[#71717A] text-[13px]">
          <i>handsal</i> — Old Norse: a deal sealed by a handshake · RFC 6749 · 7662 · 8414 · v0.1.0
        </p>
      </section>

      <section className="flex min-w-0 flex-1 basis-1/2 items-center justify-center p-8">
        <form onSubmit={handleSubmit} className="flex w-full max-w-[380px] flex-col gap-6">
          <div className="flex items-center gap-2.5 md:hidden">
            <Logo size={28} />
            <InstanceMark nameClassName="text-lg tracking-tight" />
          </div>
          <div className="flex flex-col gap-1.5">
            <h2 className="font-display font-semibold text-[26px] tracking-tight">Sign in</h2>
            <p className="text-muted">Use your admin account to manage tenants and applications.</p>
          </div>

          <div className="flex flex-col gap-4">
            <Input
              label="Email"
              type="email"
              placeholder="you@company.com"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <Input
              label="Password"
              type="password"
              placeholder="••••••••••"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {error && (
            <p role="alert" className="text-danger text-sm">
              {error}
            </p>
          )}

          <Button type="submit" size="lg" loading={login.isPending}>
            Continue
          </Button>

          <p className="text-center text-muted text-xs">
            Admin access only. Services authenticate via{" "}
            <span className="font-mono">/t/{"{tenant}"}/oauth/token</span>.
          </p>
        </form>
      </section>
    </div>
  );
}
