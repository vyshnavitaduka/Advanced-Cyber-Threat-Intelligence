import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Route: Threat Collection Proxy
  app.get("/api/threats/collect", async (req, res) => {
    try {
      const source = req.query.source as string;
      let data = "";

      if (source === "urlhaus") {
        const response = await fetch("https://urlhaus.abuse.ch/downloads/text/");
        data = await response.text();
        // Extract URLs from the text feed (skipping comments)
        const urls = data.split("\n")
          .filter(line => line && !line.startsWith("#"))
          .slice(0, 50);
        return res.json({ source: "URLhaus", type: "URL", data: urls });
      } 
      
      if (source === "blocklist") {
        const response = await fetch("https://www.blocklist.de/downloads/export-ips_all.txt");
        data = await response.text();
        const ips = data.split("\n").filter(line => line).slice(0, 50);
        return res.json({ source: "Blocklist.de", type: "IP", data: ips });
      }

      if (source === "malwarebazaar") {
        const response = await fetch("https://bazaar.abuse.ch/export/txt/sha256/recent/");
        data = await response.text();
        const hashes = data.split("\n")
          .filter(line => line && !line.startsWith("#"))
          .slice(0, 50);
        return res.json({ source: "MalwareBazaar", type: "Hash (SHA256)", data: hashes });
      }

      res.status(400).json({ error: "Invalid source" });
    } catch (error) {
      console.error("Collection error:", error);
      res.status(500).json({ error: "Failed to collect data" });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
