import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { captureAndScrubMagicFragment } from "./bootstrapAuth";
import "./index.css";
import { App } from "./App";

// Synchronously extract `#t=` into memory and clear URL fragment before mounting or any script load
captureAndScrubMagicFragment();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
