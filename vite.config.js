import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

const readRawBody = async (req) =>
  await new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolveBody(Buffer.concat(chunks).toString('utf8')));
    req.on('error', rejectBody);
  });

const resolveApiHandlerPath = (pathname) => {
  const route = String(pathname || '')
    .replace(/^\/api\/?/, '')
    .replace(/\/+$/, '');

  if (!route || route.startsWith('_')) return null;

  const filePath = resolve(process.cwd(), 'api', `${route}.js`);
  return existsSync(filePath) ? filePath : null;
};

const localApiRoutesPlugin = () => ({
  name: 'local-api-routes',
  configureServer(server) {
    server.middlewares.use(async (req, res, next) => {
      const requestUrl = req.url ? new URL(req.url, 'http://localhost') : null;
      if (!requestUrl || !requestUrl.pathname.startsWith('/api/')) {
        return next();
      }

      const handlerPath = resolveApiHandlerPath(requestUrl.pathname);
      if (!handlerPath) {
        return next();
      }

      try {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          req.body = await readRawBody(req);
        }

        res.status = (code) => {
          res.statusCode = code;
          return res;
        };

        res.json = (payload) => {
          if (!res.headersSent) {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
          }
          res.end(JSON.stringify(payload));
          return res;
        };

        const moduleUrl = `${pathToFileURL(handlerPath).href}?t=${Date.now()}`;
        const handlerModule = await import(moduleUrl);
        const handler = handlerModule?.default;

        if (typeof handler !== 'function') {
          return next();
        }

        await handler(req, res);
        if (!res.writableEnded) {
          res.end();
        }
      } catch (error) {
        if (!res.headersSent) {
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json; charset=utf-8');
        }
        res.end(
          JSON.stringify({
            error: 'Local API route failed.',
            details: String(error?.message || 'unknown'),
          }),
        );
      }
    });
  },
});

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  for (const [key, value] of Object.entries(env)) {
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }

  return {
    plugins: [react(), localApiRoutesPlugin()],
  };
});
