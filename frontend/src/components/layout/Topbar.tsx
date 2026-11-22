import { LogOut, Moon, PanelLeft, Sun, UserRound } from "lucide-react";
import { useLocation } from "react-router-dom";
import { Breadcrumbs } from "@/components/layout/Breadcrumbs";
import { BackendStatus } from "@/components/layout/BackendStatus";
import { ALL_NAV_ITEMS } from "@/components/layout/nav";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/lib/auth/authContext";
import { useTheme } from "@/lib/theme/ThemeProvider";

function usePageTitle(): string {
  const { pathname } = useLocation();
  const match = ALL_NAV_ITEMS.find((item) =>
    item.path === "/" ? pathname === "/" : pathname.startsWith(item.path),
  );
  return match?.label ?? "AI Security Analyst";
}

interface TopbarProps {
  onToggleSidebar: () => void;
}

export function Topbar({ onToggleSidebar }: TopbarProps) {
  const { theme, toggleTheme } = useTheme();
  const { user, logout } = useAuth();
  const title = usePageTitle();

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/80 px-4 backdrop-blur">
      <Button
        variant="ghost"
        size="icon"
        onClick={onToggleSidebar}
        aria-label="Toggle sidebar"
        className="shrink-0"
      >
        <PanelLeft />
      </Button>

      <div className="min-w-0 flex-1">
        <h1 className="truncate text-sm font-semibold text-foreground">{title}</h1>
        <div className="hidden md:block">
          <Breadcrumbs />
        </div>
      </div>

      <BackendStatus />

      <Button
        variant="ghost"
        size="icon"
        onClick={toggleTheme}
        aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      >
        {theme === "dark" ? <Sun /> : <Moon />}
      </Button>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="icon" aria-label="Account menu">
            <UserRound />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel className="truncate">
            {user?.email ?? "Account"}
          </DropdownMenuLabel>
          {user && user.roles.length > 0 ? (
            <p className="truncate px-2 pb-1 text-xs text-muted-foreground">
              {user.roles.join(", ")}
            </p>
          ) : null}
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => void logout()}>
            <LogOut />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  );
}
