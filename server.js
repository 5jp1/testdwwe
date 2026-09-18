import { spawn } from 'node:child_process';

const args = process.argv.slice(2);
let port = 3000;
let host = '0.0.0.0';

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port' && args[i + 1]) {
    port = parseInt(args[i + 1], 10) || 3000;
    i++;
  } else if (args[i] === '--host' && args[i + 1]) {
    host = args[i + 1];
    i++;
  }
}

// Ensure the dev server always binds to port 3000 as required by the reverse proxy
if (port === 8080 || !port) {
  port = 3000;
}

console.log(`Starting PHP server on ${host}:${port}...`);
const php = spawn('php', ['-S', `${host}:${port}`], {
  stdio: 'inherit',
  cwd: process.cwd()
});

php.on('error', (err) => {
  console.error('Failed to start PHP process:', err);
  process.exit(1);
});

php.on('close', (code) => {
  console.log(`PHP process exited with code ${code}`);
  process.exit(code ?? 0);
});

process.on('SIGINT', () => {
  php.kill('SIGINT');
  process.exit(0);
});

process.on('SIGTERM', () => {
  php.kill('SIGTERM');
  process.exit(0);
});
