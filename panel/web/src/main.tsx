import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { AppProvider } from "./store";
import { startCosmos } from "./scene-cosmos";
import "./tokens.css";
import "./app.css";
import "./pages.css";
import "./skin.css";
import "./cosmos.css";

// The space behind every screen: one fixed canvas, outside React, started once.
const sky = document.createElement("canvas");
sky.id = "cosmos";
sky.setAttribute("aria-hidden", "true");
document.body.prepend(sky);
startCosmos(sky);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AppProvider>
      <App />
    </AppProvider>
  </StrictMode>,
);
