export type ThemePreference = "light" | "dark" | "system";

export const THEME_KEY = "soundcheck-theme";

export const THEME_BOOTSTRAP = `(function(){try{var p=localStorage.getItem("${THEME_KEY}")||"system";var d=p==="dark"||(p==="system"&&matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.setAttribute("data-theme",d?"dark":"light")}catch(e){}})()`;

export function readPreference(): ThemePreference {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return value === "light" || value === "dark" ? value : "system";
  } catch {
    return "system";
  }
}

export function applyPreference(preference: ThemePreference) {
  const dark =
    preference === "dark" ||
    (preference === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
}

export const SIDEBAR_KEY = "soundcheck-sidebar";

/** Applied before first paint so a collapsed sidebar never flashes open. */
export const SIDEBAR_BOOTSTRAP = `(function(){try{if(localStorage.getItem("${SIDEBAR_KEY}")==="collapsed")document.documentElement.setAttribute("data-sidebar","collapsed")}catch(e){}})()`;
