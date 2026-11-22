import { createBrowserRouter } from "react-router-dom";
import { RequireAuth } from "@/components/auth/RequireAuth";
import { AppShell } from "@/components/layout/AppShell";
import { LoginPage } from "@/features/auth/LoginPage";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { AssessmentsPage } from "@/features/assessments/AssessmentsPage";
import { AssessmentDetailPage } from "@/features/assessments/AssessmentDetailPage";
import { AssessmentFindingsPage } from "@/features/findings/AssessmentFindingsPage";
import { AssessmentAttackSurfacePage } from "@/features/attack-surface/AssessmentAttackSurfacePage";
import { AssessmentReportPage } from "@/features/reports/AssessmentReportPage";
import { WorkflowsPage } from "@/features/workflows/WorkflowsPage";
import { WorkflowDetailPage } from "@/features/workflows/WorkflowDetailPage";
import { AssessmentEvidencePage } from "@/features/evidence/AssessmentEvidencePage";
import { RepositoriesPage } from "@/features/repositories/RepositoriesPage";
import { AttackSurfacePage } from "@/features/attack-surface/AttackSurfacePage";
import { FindingsPage } from "@/features/findings/FindingsPage";
import { EvidencePage } from "@/features/evidence/EvidencePage";
import { ReportsPage } from "@/features/reports/ReportsPage";
import { AuditLogsPage } from "@/features/audit/AuditLogsPage";
import { AdministrationPage } from "@/features/administration/AdministrationPage";
import { SettingsPage } from "@/features/settings/SettingsPage";
import { NotFoundPage } from "@/features/NotFoundPage";

export const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  {
    element: <RequireAuth />,
    children: [
      {
        path: "/",
        element: <AppShell />,
        children: [
          { index: true, element: <OverviewPage /> },
          { path: "assessments", element: <AssessmentsPage /> },
          { path: "assessments/:id", element: <AssessmentDetailPage /> },
          { path: "assessments/:id/findings", element: <AssessmentFindingsPage /> },
          { path: "assessments/:id/attack-surface", element: <AssessmentAttackSurfacePage /> },
          { path: "assessments/:id/report", element: <AssessmentReportPage /> },
          { path: "assessments/:id/workflows", element: <WorkflowsPage /> },
          { path: "assessments/:id/workflows/:workflowId", element: <WorkflowDetailPage /> },
          { path: "assessments/:id/evidence", element: <AssessmentEvidencePage /> },
          { path: "repositories", element: <RepositoriesPage /> },
          { path: "attack-surface", element: <AttackSurfacePage /> },
          { path: "findings", element: <FindingsPage /> },
          { path: "evidence", element: <EvidencePage /> },
          { path: "reports", element: <ReportsPage /> },
          { path: "audit", element: <AuditLogsPage /> },
          { path: "administration", element: <AdministrationPage /> },
          { path: "settings", element: <SettingsPage /> },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
  },
]);
