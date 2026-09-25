import { Navigate, Route, Routes } from "react-router-dom";
import AppShell from "./components/ui/AppShell";
import Drift from "./pages/Drift";
import Findings from "./pages/Findings";
import FileSelection from "./pages/FileSelection";
import NewScan from "./pages/NewScan";
import Overview from "./pages/Overview";
import Roadmap from "./pages/Roadmap";

// The six screens of SPEC.md §13, under one shell. Scan-scoped screens share
// a `/scans/:scanId` prefix so the sidebar can link between them. Each screen
// renders its own PageHeader + PageBody inside the shell.
export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<NewScan />} />
        <Route path="/scans/:scanId/files" element={<FileSelection />} />
        <Route path="/scans/:scanId" element={<Overview />} />
        <Route path="/scans/:scanId/findings" element={<Findings />} />
        <Route path="/scans/:scanId/drift" element={<Drift />} />
        <Route path="/scans/:scanId/roadmap" element={<Roadmap />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
