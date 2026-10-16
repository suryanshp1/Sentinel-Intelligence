import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@fontsource-variable/inter";
import "@xyflow/react/dist/style.css";
import "./styles.css";
import App from "./App";
import { ThemeProvider } from "./theme";
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 60000, refetchOnWindowFocus: false },
  },
});
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
