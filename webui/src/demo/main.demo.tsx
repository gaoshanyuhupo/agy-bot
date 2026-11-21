import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { installDemoRuntime } from "./demoRuntime";
import "../index.css";
import { App } from "../App";

// Install global subpath history guard, EventSource, WebSocket, and fail-closed fetch BEFORE mounting <App />
installDemoRuntime();
document.title = "AGY Studio · 交互演示版";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
