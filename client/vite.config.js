import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Dev: /api is proxied to the Express server, so the browser only ever talks to one origin.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, host: true, proxy: { '/api': { target: 'http://127.0.0.1:4000', changeOrigin: true } } },
  preview: { port: 4173, host: true, proxy: { '/api': { target: 'http://127.0.0.1:4000', changeOrigin: true } } },
  build: { target: 'es2020', sourcemap: false, chunkSizeWarningLimit: 700 }
});
