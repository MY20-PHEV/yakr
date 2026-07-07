document.addEventListener("DOMContentLoaded", () => {
  const current = location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".nav-section a").forEach((link) => {
    const href = link.getAttribute("href");
    if (href === current || (current === "" && href === "index.html")) {
      link.classList.add("active");
    }
  });

  if (typeof mermaid !== "undefined") {
    mermaid.initialize({
      startOnLoad: true,
      theme: "dark",
      themeVariables: {
        primaryColor: "#1a2433",
        primaryTextColor: "#e8edf4",
        primaryBorderColor: "#5eb3ff",
        lineColor: "#5eb3ff",
        secondaryColor: "#161d27",
        tertiaryColor: "#121820",
        fontFamily: "Inter, system-ui, sans-serif",
      },
      flowchart: { curve: "basis", padding: 16 },
      sequence: { actorMargin: 60, messageMargin: 40 },
    });
  }
});
