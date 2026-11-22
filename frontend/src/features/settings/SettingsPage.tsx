import { Monitor, Moon, Sun } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useTheme } from "@/lib/theme/ThemeProvider";

export function SettingsPage() {
  const { theme, setTheme } = useTheme();
  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Client-side preferences. The backend exposes no server settings endpoint; account details will come from the authenticated profile in Stage 2."
      />
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Appearance</CardTitle>
          <CardDescription>Dark-first interface. Your choice is stored in this browser.</CardDescription>
        </CardHeader>
        <CardContent className="flex gap-2">
          <Button variant={theme === "dark" ? "default" : "outline"} size="sm" onClick={() => setTheme("dark")}>
            <Moon /> Dark
          </Button>
          <Button variant={theme === "light" ? "default" : "outline"} size="sm" onClick={() => setTheme("light")}>
            <Sun /> Light
          </Button>
          <Button variant="outline" size="sm" disabled title="System sync arrives later">
            <Monitor /> System
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
