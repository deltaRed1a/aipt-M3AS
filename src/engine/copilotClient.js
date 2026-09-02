import { spawn } from 'node:child_process';
import { config } from '../config/index.js';
import { simulateModelResponse } from './simulator.js';

/**
 * Builds the GitHub Copilot CLI argument list for a model.
 * Extra per-model flags come from the registry (`cliArgs`) so new models or new
 * CLI capabilities can be wired up without touching this code.
 */
export function buildCliArgs(model, prompt) {
  return [
    '-p',
    prompt,
    '--model',
    model.cliModel,
    '--allow-all-tools',
    '--no-color',
    ...model.cliArgs,
  ];
}

function runProcess(bin, args, { cwd, timeoutMs, signal }) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      cwd,
      signal,
      // No shell: arguments are passed directly, so untrusted values cannot be
      // interpreted as shell syntax.
      shell: false,
      env: { ...process.env, NO_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`Model process timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${bin} exited with code ${code}: ${stderr.trim().slice(0, 2000)}`));
    });
  });
}

/**
 * Runs a single model against a checked-out source tree.
 * Returns the raw text response of the model.
 */
export async function runModel({ model, prompt, cwd, signal, engine = config.engine }) {
  if (engine === 'simulate') {
    return simulateModelResponse({ model, cwd });
  }
  const { stdout } = await runProcess(config.copilotBin, buildCliArgs(model, prompt), {
    cwd,
    timeoutMs: config.modelTimeoutMs,
    signal,
  });
  return stdout;
}
