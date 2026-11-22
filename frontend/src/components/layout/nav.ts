import type { LucideIcon } from "lucide-react";
import {
  ClipboardList,
  FileSearch,
  FileText,
  FolderGit2,
  LayoutDashboard,
  Network,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

/** Backend role name that unlocks admin-only navigation. UI hint only. */
export const ADMIN_ROLE = "Admin";

export interface NavItem {
  label: string;
  path: string;
  icon: LucideIcon;
  /** Role hint for the UI only; the backend remains the authoritative boundary. */
  adminOnly?: boolean;
}

export interface NavSection {
  heading?: string;
  items: NavItem[];
}

/**
 * Navigation is limited to sections backed by real APIs. Each route maps to one
 * or more existing backend endpoints; no speculative features are listed.
 */
export const NAV_SECTIONS: NavSection[] = [
  {
    items: [{ label: "Overview", path: "/", icon: LayoutDashboard }],
  },
  {
    heading: "Assess",
    items: [
      { label: "Assessments", path: "/assessments", icon: ClipboardList },
      { label: "Repositories", path: "/repositories", icon: FolderGit2 },
      { label: "Attack Surface", path: "/attack-surface", icon: Network },
    ],
  },
  {
    heading: "Analyze",
    items: [
      { label: "Findings", path: "/findings", icon: ShieldAlert },
      { label: "Evidence", path: "/evidence", icon: FileSearch },
      { label: "Reports", path: "/reports", icon: FileText },
    ],
  },
  {
    heading: "Govern",
    items: [
      { label: "Audit Logs", path: "/audit", icon: ScrollText, adminOnly: true },
      { label: "Administration", path: "/administration", icon: ShieldCheck, adminOnly: true },
      { label: "Settings", path: "/settings", icon: Settings },
    ],
  },
];

export const ALL_NAV_ITEMS: NavItem[] = NAV_SECTIONS.flatMap((section) => section.items);
