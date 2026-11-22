import { ShieldHalf } from "lucide-react";
import { NavLink } from "react-router-dom";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ADMIN_ROLE, NAV_SECTIONS, type NavItem } from "@/components/layout/nav";
import { useAuth } from "@/lib/auth/authContext";
import { cn } from "@/lib/utils";

interface SidebarProps {
  collapsed: boolean;
  onNavigate?: () => void;
}

function SidebarItem({ item, collapsed, onNavigate }: { item: NavItem; collapsed: boolean; onNavigate?: () => void }) {
  const Icon = item.icon;
  const link = (
    <NavLink
      to={item.path}
      end={item.path === "/"}
      onClick={onNavigate}
      className={({ isActive }) =>
        cn(
          "group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium outline-none transition-colors focus-visible:ring-2 focus-visible:ring-ring",
          collapsed && "justify-center px-0",
          isActive
            ? "bg-sidebar-accent text-foreground"
            : "text-sidebar-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
        )
      }
    >
      {({ isActive }) => (
        <>
          <span
            className={cn(
              "flex h-5 w-1 shrink-0 rounded-full transition-colors",
              isActive ? "bg-primary" : "bg-transparent",
              collapsed && "hidden",
            )}
            aria-hidden
          />
          <Icon className="size-[18px] shrink-0" />
          {!collapsed && <span className="truncate">{item.label}</span>}
        </>
      )}
    </NavLink>
  );

  if (!collapsed) return link;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">{item.label}</TooltipContent>
    </Tooltip>
  );
}

export function Sidebar({ collapsed, onNavigate }: SidebarProps) {
  const { hasRole } = useAuth();
  const isAdmin = hasRole(ADMIN_ROLE);
  // Role filtering is UX only; admin-only routes stay backend-enforced regardless.
  const sections = NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter((item) => !item.adminOnly || isAdmin),
  })).filter((section) => section.items.length > 0);

  return (
    <div className="flex h-full flex-col bg-sidebar">
      <div className={cn("flex h-14 items-center gap-2.5 border-b border-sidebar-border px-4", collapsed && "justify-center px-0")}>
        <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary">
          <ShieldHalf className="size-5" />
        </div>
        {!collapsed && (
          <div className="leading-tight">
            <p className="text-sm font-semibold text-foreground">AI Security Analyst</p>
            <p className="text-[11px] text-muted-foreground">Assessment platform</p>
          </div>
        )}
      </div>

      <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-4" aria-label="Primary">
        {sections.map((section, index) => (
          <div key={section.heading ?? index} className="space-y-1">
            {section.heading && !collapsed ? (
              <p className="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                {section.heading}
              </p>
            ) : null}
            {section.items.map((item) => (
              <SidebarItem key={item.path} item={item} collapsed={collapsed} onNavigate={onNavigate} />
            ))}
          </div>
        ))}
      </nav>

      <div className={cn("border-t border-sidebar-border p-3", collapsed && "px-0 text-center")}>
        <p className={cn("text-[11px] text-muted-foreground", collapsed && "hidden")}>
          Backend-authoritative. UI reflects real capabilities only.
        </p>
      </div>
    </div>
  );
}
