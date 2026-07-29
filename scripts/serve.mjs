// dev-only static server for verifying the merged OS (not part of the OS itself)
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

const ROOT = process.cwd();
const PORT = process.env.PORT || 8137;
const TYPES = {
  '.html': 'text/html', '.mjs': 'text/javascript', '.js': 'text/javascript',
  '.json': 'application/json', '.css': 'text/css', '.svg': 'image/svg+xml',
};

createServer(async (req, res) => {
  try {
    let p = decodeURIComponent(req.url.split('?')[0]);
    if (p === '/') p = '/fallos.html';
    const full = normalize(join(ROOT, p));
    if (!full.startsWith(ROOT)) { res.writeHead(403); return res.end('forbidden'); }
    const body = await readFile(full);
    res.writeHead(200, {
      'content-type': TYPES[extname(full)] || 'application/octet-stream',
      'cache-control': 'no-store',
    });
    res.end(body);
  } catch (e) {
    res.writeHead(404); res.end('not found: ' + req.url);
  }
}).listen(PORT, () => console.log(`niceassos dev server · http://localhost:${PORT}`));
