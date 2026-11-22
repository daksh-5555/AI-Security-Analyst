import type { LucideIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/states/EmptyState";

interface StagePlaceholderProps {
  icon: LucideIcon;
  title: string;
  /** The real backend endpoints this screen will integrate. Shown for transparency. */
  endpoints: string[];
  stage: string;
  description: string;
}

/**
 * Honest placeholder for a screen whose data integration lands in a later stage.
 * It renders no fabricated data; it states exactly which backend endpoints will
 * power the screen and when they are wired.
 */
export function StagePlaceholder({ icon, title, endpoints, stage, description }: StagePlaceholderProps) {
  return (
    <div className="space-y-4">
      <EmptyState icon={icon} title={title} description={description} />
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle className="text-sm">Backend integration</CardTitle>
          <Badge variant="muted">Wired in {stage}</Badge>
        </CardHeader>
        <CardContent className="space-y-2">
          <p className="text-xs text-muted-foreground">
            This screen will read from the following existing API endpoints. No data is shown until
            the integration stage is approved.
          </p>
          <ul className="space-y-1">
            {endpoints.map((endpoint) => (
              <li key={endpoint} className="font-mono text-xs text-foreground/80">
                {endpoint}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
