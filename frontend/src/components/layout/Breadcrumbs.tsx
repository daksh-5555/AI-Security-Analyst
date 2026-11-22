import { Fragment } from "react";
import { ChevronRight } from "lucide-react";
import { Link, useLocation } from "react-router-dom";
import { ALL_NAV_ITEMS } from "@/components/layout/nav";

function labelFor(segment: string): string {
  const match = ALL_NAV_ITEMS.find((item) => item.path === `/${segment}`);
  if (match) return match.label;
  return segment.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

/** Route-derived breadcrumb trail. */
export function Breadcrumbs() {
  const { pathname } = useLocation();
  const segments = pathname.split("/").filter(Boolean);

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-sm text-muted-foreground">
      <Link to="/" className="transition-colors hover:text-foreground">
        Home
      </Link>
      {segments.map((segment, index) => {
        const href = `/${segments.slice(0, index + 1).join("/")}`;
        const isLast = index === segments.length - 1;
        return (
          <Fragment key={href}>
            <ChevronRight className="size-3.5 shrink-0 opacity-50" aria-hidden />
            {isLast ? (
              <span className="font-medium text-foreground" aria-current="page">
                {labelFor(segment)}
              </span>
            ) : (
              <Link to={href} className="transition-colors hover:text-foreground">
                {labelFor(segment)}
              </Link>
            )}
          </Fragment>
        );
      })}
    </nav>
  );
}
