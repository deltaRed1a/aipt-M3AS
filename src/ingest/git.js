import { spawn } from 'node:child_process';

const ALLOWED_HOSTS = new Set([
  'github.com',
  'www.github.com',
  'dev.azure.com',
  'ssh.dev.azure.com',
]);

function isAllowedHost(hostname) {
  return ALLOWED_HOSTS.has(hostname) || hostname.endsWith('.visualstudio.com');
}

/**
 * Validates a repository URL before it is handed to `git`.
 * Only https URLs on known GitHub / Azure DevOps hosts are accepted, which
 * blocks SSRF to internal hosts and git transports such as file:// or ext::.
 */
export function parseRepoUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    throw new Error('Repository URL is required');
  }
  const value = rawUrl.trim();
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Repository URL is not a valid URL');
  }
  if (url.protocol !== 'https:') {
    throw new Error('Only https:// repository URLs are supported');
  }
  if (!isAllowedHost(url.hostname)) {
    throw new Error(`Repository host "${url.hostname}" is not allowed`);
  }
  if (url.username || url.password) {
    throw new Error('Credentials embedded in the repository URL are not allowed');
  }
  const provider = url.hostname.endsWith('github.com') ? 'github' : 'ado';
  return { url: url.toString(), provider, host: url.hostname, path: url.pathname };
}

function credentialUrl(url, provider) {
  const token = provider === 'github' ? process.env.GITHUB_TOKEN : process.env.ADO_PAT;
  if (!token) return url;
  const parsed = new URL(url);
  parsed.username = provider === 'github' ? 'x-access-token' : 'pat';
  parsed.password = token;
  return parsed.toString();
}

/**
 * Shallow-clones a repository into `destination`.
 * The URL is passed after `--` so it can never be read as a git option, and no
 * shell is involved.
 */
export function cloneRepository({ url, provider, destination, branch, timeoutMs = 10 * 60 * 1000 }) {
  const args = ['clone', '--depth', '1', '--single-branch'];
  if (branch) args.push('--branch', branch);
  args.push('--', credentialUrl(url, provider), destination);
  return new Promise((resolve, reject) => {
    const child = spawn('git', args, {
      shell: false,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: 'true' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('git clone timed out'));
    }, timeoutMs);
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      // Never surface the stderr verbatim: it can contain the credential URL.
      if (code === 0) resolve(destination);
      else reject(new Error(`git clone failed (exit ${code}): ${stderr.replace(/https:\/\/[^@\s]+@/g, 'https://***@').slice(0, 500)}`));
    });
  });
}
