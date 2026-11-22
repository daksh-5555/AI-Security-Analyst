import { Compass } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/states/EmptyState";

export function NotFoundPage() {
  return (
    <div className="mx-auto max-w-lg py-10">
      <EmptyState
        icon={Compass}
        title="Page not found"
        description="This route does not exist in the application."
        action={
          <Button asChild size="sm">
            <Link to="/">Back to overview</Link>
          </Button>
        }
      />
    </div>
  );
}
