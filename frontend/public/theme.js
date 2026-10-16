// Runs before the app and styles load to avoid flashing the wrong theme.
(() => {
  let preference;
  try { preference = localStorage.getItem("sentinel-theme"); } catch { /* Storage may be unavailable. */ }
  const theme = preference === "light" || preference === "dark"
    ? preference
    : window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#090909" : "#f6f7f9");
})();
