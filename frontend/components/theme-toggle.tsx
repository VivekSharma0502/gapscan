"use client";

import { Moon, Sun } from "lucide-react";
import { useLayoutEffect } from "react";

import { Button } from "@/components/ui/button";

// Also read by the inline script in app/layout.tsx.
const STORAGE_KEY = "scankit.theme";

function readStoredTheme(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

export function ThemeToggle() {
  // React's dev-only remount resets <html>, clearing what the inline script set.
  useLayoutEffect(() => {
    if (readStoredTheme() === "light") {
      document.documentElement.classList.remove("dark");
    }
  }, []);

  function toggle() {
    const isDark = document.documentElement.classList.toggle("dark");
    try {
      localStorage.setItem(STORAGE_KEY, isDark ? "dark" : "light");
    } catch {
      // Storage is blocked. The theme still changes for this page.
    }
  }

  // The icons switch through CSS, so they are right before React has loaded.
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={toggle}
      aria-label="Switch between light and dark theme"
    >
      <Sun className="hidden dark:block" />
      <Moon className="dark:hidden" />
    </Button>
  );
}
