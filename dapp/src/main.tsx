import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ThirdwebProvider } from "thirdweb/react";
import PorDashboardPage from "./pages/PorDashboard";
import SubmitPage from "./pages/Submit";
import VerifyPage from "./pages/Verify";
import ResultPage from "./pages/Result";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThirdwebProvider>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          <Route path="/" element={<SubmitPage />} />
          <Route path="/verify" element={<VerifyPage />} />
          <Route path="/result/:requestId" element={<ResultPage />} />
          <Route path="/por" element={<PorDashboardPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </ThirdwebProvider>
  </React.StrictMode>
);
