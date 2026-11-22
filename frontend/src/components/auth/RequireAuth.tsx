import { Loader2 } from "lucide-react";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "@/lib/auth/authContext";

/**
 * Gate for the authenticated app. While the initial silent refresh is in flight
 * it shows a neutral loader; an anonymous visitor is redirected to the login page
 * with the attempted location preserved so they return there after signing in.
 * This is UX only — the backend remains the authoritative authorization boundary.
 */
export function RequireAuth() {
  const { status } = useAuth();
  const location = useLocation();

  if (status === "loading") {
    return (
      <div
        className="flex min-h-screen items-center justify-center bg-background text-muted-foreground"
        role="status"
        aria-label="Checking your session"
      >
        <Loader2 className="size-6 animate-spin" />
      </div>
    );
  }

  if (status === "anonymous") {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <Outlet />;
}
