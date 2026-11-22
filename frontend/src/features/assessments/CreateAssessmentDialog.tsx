import { useState, type FormEvent } from "react";
import { Loader2, Plus } from "lucide-react";
import { ApiError } from "@/lib/api/client";
import { useCreateAssessment, type AssessmentType } from "@/lib/api/assessments";
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
import { ASSESSMENT_TYPE_LABELS, CREATABLE_ASSESSMENT_TYPES } from "./labels";

interface CreateAssessmentDialogProps {
  onCreated: (id: string) => void;
}

export function CreateAssessmentDialog({ onCreated }: CreateAssessmentDialogProps) {
  const [open, setOpen] = useState(false);
  const [type, setType] = useState<AssessmentType>("repository");
  const [error, setError] = useState<string | null>(null);
  const create = useCreateAssessment();

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    try {
      const created = await create.mutateAsync({ assessment_type: type });
      setOpen(false);
      setType("repository");
      onCreated(created.id);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.userMessage : "Unable to create the assessment.");
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setError(null);
      }}
    >
      <DialogTrigger asChild>
        <Button>
          <Plus />
          New assessment
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New assessment</DialogTitle>
          <DialogDescription>
            Choose what to assess. You configure its source on the next screen.
          </DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={onSubmit}>
          <div className="space-y-2">
            <Label htmlFor="assessment-type">Type</Label>
            <select
              id="assessment-type"
              value={type}
              onChange={(event) => setType(event.target.value as AssessmentType)}
              disabled={create.isPending}
              className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {CREATABLE_ASSESSMENT_TYPES.map((value) => (
                <option key={value} value={value}>
                  {ASSESSMENT_TYPE_LABELS[value]}
                </option>
              ))}
            </select>
          </div>
          {error ? (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          ) : null}
          <DialogFooter>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? <Loader2 className="animate-spin" /> : null}
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
