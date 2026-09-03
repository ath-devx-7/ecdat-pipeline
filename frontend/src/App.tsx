import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Drift from "./pages/Drift";
import Findings from "./pages/Findings";
import FileSelection from "./pages/FileSelection";
import NewScan from "./pages/NewScan";
import Overview from "./pages/Overview";
import Roadmap from "./pages/Roadmap";

// The six screens of SPEC.md §13, under one layout. Scan-scoped screens share
// a `/scans/:scanId` prefix so the tab bar can link between them.
export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
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
