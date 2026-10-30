import { request } from 'node:http';

export interface DockerResponse {
  status: number;
  body: unknown;
}

/** The only operation the runner needs from Docker: one Engine API call. Injected, so tests use a fake. */
export interface DockerApi {
  call(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown): Promise<DockerResponse>;
}

/**
 * Docker Engine API over its socket, with node:http (no SDK dependency: the
 * runner holds root-equivalent power, so its code and dependencies stay minimal).
 * API 1.44 is the oldest version current engines still accept.
 */
export function dockerSocket(socketPath: string, timeoutMs = 20_000): DockerApi {
  return {
    call: (method, path, body) =>
      new Promise((resolve, reject) => {
        const payload = body === undefined ? undefined : JSON.stringify(body);
        const req = request(
          {
            socketPath,
            method,
            path: `/v1.44${path}`,
            headers: payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
            timeout: timeoutMs,
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c: Buffer) => chunks.push(c));
            res.on('end', () => {
              const text = Buffer.concat(chunks).toString('utf8');
              let parsed: unknown = text;
              try {
                parsed = text ? JSON.parse(text) : null;
              } catch {
                // Some endpoints answer plain text; keep it as is.
              }
              resolve({ status: res.statusCode ?? 0, body: parsed });
            });
          },
        );
        req.on('timeout', () => req.destroy(new Error('docker API timeout')));
        req.on('error', reject);
        req.end(payload);
      }),
  };
}
