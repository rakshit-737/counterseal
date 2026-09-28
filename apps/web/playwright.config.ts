import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { defineConfig, devices } from "@playwright/test";

const webDirectory = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  testDir: resolve(webDirectory, "e2e"),
  fullyParallel: true,
  timeout: 15_000,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1",
    cwd: resolve(webDirectory, "../.."),
    url: "http://127.0.0.1:5173",
    reuseExistingServer: true,
  },
});
