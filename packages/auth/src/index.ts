import { KilnError } from "@kiln/core";
export type Scope = "read" | "operate" | "admin";
export interface Identity {
  subject: string;
  projectId: string;
  scopes: Scope[];
  infrastructure: boolean;
}
export class TokenAuthenticator {
  constructor(private readonly token: string | undefined, private readonly infrastructureToken?: string) {}
  authenticate(header: string | undefined): Identity {
    if (!this.token)
      throw new KilnError(
        "UNAUTHENTICATED",
        401,
        "API authentication is not configured",
      );
    const supplied = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
    const infrastructure = Boolean(this.infrastructureToken && supplied === this.infrastructureToken);
    if (!supplied || (supplied !== this.token && !infrastructure))
      throw new KilnError("UNAUTHENTICATED", 401, "Authentication required");
    return {
      subject: "local-development",
      projectId: "default",
      scopes: ["read", "operate", "admin"],
      infrastructure,
    };
  }
}
export function requireInfrastructure(identity: Identity): void {
  if (!identity.infrastructure)
    throw new KilnError("UNAUTHORIZED", 403, "Infrastructure administrator credential required");
}
export function requireScope(identity: Identity, scope: Scope): void {
  if (!identity.scopes.includes(scope))
    throw new KilnError("UNAUTHORIZED", 403, "Credential lacks required scope");
}
