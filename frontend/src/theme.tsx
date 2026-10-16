import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { Moon, Sun } from "lucide-react";

type Theme = "dark" | "light";
const storageKey = "sentinel-theme";
const ThemeContext = createContext<{ theme: Theme; toggle: () => void } | null>(null);

function readPreference(): Theme | null {
  try {
    const saved = localStorage.getItem(storageKey);
    return saved === "light" || saved === "dark" ? saved : null;
  } catch { return null; }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const preference = useRef(readPreference());
  const [theme, setTheme] = useState<Theme>(() => document.documentElement.dataset.theme === "light" ? "light" : "dark");
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const sync = () => {
      setTheme(preference.current ?? (media.matches ? "dark" : "light"));
    };
    const onStorage = (event: StorageEvent) => {
      if (event.key === storageKey || event.key === null) {
        preference.current = readPreference();
        sync();
      }
    };
    media.addEventListener("change", sync);
    window.addEventListener("storage", onStorage);
    return () => {
      media.removeEventListener("change", sync);
      window.removeEventListener("storage", onStorage);
    };
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#090909" : "#f6f7f9");
  }, [theme]);
  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    preference.current = next;
    try { localStorage.setItem(storageKey, next); } catch { /* Keep the choice for this session. */ }
    setTheme(next);
  };
  return <ThemeContext.Provider value={{ theme, toggle }}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTheme requires ThemeProvider");
  return context;
}

export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const label = `Switch to ${theme === "dark" ? "light" : "dark"} mode`;
  return <button type="button" className="icon-button theme-toggle" onClick={toggle} aria-label={label} title={label}>
    {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
  </button>;
}
