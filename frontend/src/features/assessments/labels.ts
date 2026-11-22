import type { AssessmentType } from "@/lib/api/assessments";

/** Human labels for the backend assessment types. */
export const ASSESSMENT_TYPE_LABELS: Record<AssessmentType, string> = {
  repository: "Repository",
  web_security: "Web Security",
  performance: "Performance",
};

export function assessmentTypeLabel(type: string): string {
  return ASSESSMENT_TYPE_LABELS[type as AssessmentType] ?? type;
}

/** Assessment types a user can create today (web-target config lands in a later stage). */
export const CREATABLE_ASSESSMENT_TYPES: AssessmentType[] = [
  "repository",
  "web_security",
  "performance",
];
