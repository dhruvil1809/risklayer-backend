import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// https://vite.dev/config/
export default defineConfig({
  envDir: "../../", // Use the root .env file for the frontend variables
  cacheDir: ".vite_cache", // Prevent creating node_modules for just the vite cache
  plugins: [tailwindcss(), react()],
});
