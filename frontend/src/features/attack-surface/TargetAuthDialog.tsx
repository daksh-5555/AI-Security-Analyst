import { useState, type FormEvent, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import { ApiError } from "@/lib/api/client";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";

export interface TargetAuthData {
  baseUrl?: string;
  statement: string;
}

interface TargetAuthDialogProps {
  mode: "register" | "authorize";
  trigger: ReactNode;
  onConfirm: (data: TargetAuthData) => Promise<void>;
}

/**
 * Collects the operator's explicit authorization for a web target. The confirm
 * checkbox maps to the backend's required `confirm_authorized: true`; the UI never
 * sends an authorization the user did not explicitly make.
 */
export function TargetAuthDialog({ mode, trigger, onConfirm }: TargetAuthDialogProps) {
  const [open, setOpen] = useState(false);
  const [baseUrl, setBaseUrl] = useState("");
  const [statement, setStatement] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const reset = () => {
    setBaseUrl("");
    setStatement("");
    setConfirmed(false);
    setError(null);
  };

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    if (mode === "register" && !baseUrl.trim()) {
      setError("Enter the target base URL.");
      return;
    }
    if (!statement.trim()) {
      setError("Describe the basis for your authorization to test this target.");
      return;
    }
    if (!confirmed) {
      setError("You must confirm you are authorized to test this target.");
      return;
    }
    setPending(true);
    try {
      await onConfirm({ baseUrl: baseUrl.trim() || undefined, statement: statement.trim() });
      setOpen(false);
      reset();
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.userMessage : "The request could not be completed.");
    } finally {
      setPending(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) reset();
      }}
    >
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {mode === "register" ? "Register web target" : "Authorize target"}
          </DialogTitle>
          <DialogDescription>
            Only test targets you are authorized to assess. This authorization is recorded.
          </DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={onSubmit}>
          {mode === "register" ? (
            <div className="space-y-2">
              <Label htmlFor="target-base-url">Base URL</Label>
              <Input
                id="target-base-url"
                value={baseUrl}
                onChange={(event) => setBaseUrl(event.target.value)}
                placeholder="https://staging.example.com"
                disabled={pending}
                autoComplete="off"
              />
            </div>
          ) : null}
          <div className="space-y-2">
            <Label htmlFor="target-statement">Authorization statement</Label>
            <textarea
              id="target-statement"
              value={statement}
              onChange={(event) => setStatement(event.target.value)}
              disabled={pending}
              rows={3}
              placeholder="e.g. Written authorization from the target owner, engagement #1234."
              className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
            />
          </div>
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
              disabled={pending}
              className="mt-0.5 size-4 rounded border-input accent-primary"
            />
            <span>I confirm I am authorized to test this target.</span>
          </label>
          {error ? (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          ) : null}
          <DialogFooter>
            <Button type="submit" disabled={pending}>
              {pending ? <Loader2 className="animate-spin" /> : null}
              {mode === "register" ? "Register" : "Authorize"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
