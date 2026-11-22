import { ArrowLeft } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useAssessmentQuery } from "@/lib/api/assessments";
import { Button } from "@/components/ui/button";
import { assessmentTypeLabel } from "@/features/assessments/labels";
import { TargetsCard } from "./TargetsCard";
import { AttackSurfaceSummaryCard } from "./AttackSurfaceSummaryCard";

export function AssessmentAttackSurfacePage() {
  const { id = "" } = useParams();
  const assessment = useAssessmentQuery(id);
  const isWebSecurity = assessment.data?.assessment_type === "web_security";

  return (
    <div className="space-y-5">
      <div>
        <Button asChild variant="ghost" size="sm" className="mb-2 -ml-2 text-muted-foreground">
          <Link to={`/assessments/${id}`}>
            <ArrowLeft />
            {assessment.data ? `${assessmentTypeLabel(assessment.data.assessment_type)} assessment` : "Assessment"}
          </Link>
        </Button>
        <h2 className="text-xl font-semibold tracking-tight text-foreground">Attack surface</h2>
      </div>

      <TargetsCard assessmentId={id} isWebSecurity={isWebSecurity} />
      <AttackSurfaceSummaryCard assessmentId={id} />
    </div>
  );
}
