import { createHash, timingSafeEqual } from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import type { Logger } from 'pino';
import { z } from 'zod';
import { INSTANCE_ID, LAB_IDS } from '../catalog.js';
import { ENVIRONMENT_IDS } from '../environments.js';
import { EnvironmentMissing, type EnvironmentController } from './environments.js';
import { LabAlreadyRunning, LabImageMissing, type LabRunner } from './runner.js';

const startSchema = z
  .object({
    instanceId: z.string().regex(INSTANCE_ID),
    lab: z.enum(LAB_IDS),
    flag: z.string().regex(/^BASTION\{[0-9a-f]{32}\}$/),
    ttlSeconds: z.number().int().min(60).max(14_400),
  })
  .strict();

const environmentSchema = z.object({ id: z.enum(ENVIRONMENT_IDS) }).strict();

const digest = (v: string) => createHash('sha256').update(v).digest();

/**
 * Internal API of the lab runner. Only the platform calls it, over a network
 * that nothing else joins, with a shared token. Whoever reaches it can start
 * and stop lab containers, nothing more: no image, command, mount or port is
 * ever taken from the request. For shared environments (ADR 0013), it can start,
 * stop and inspect the containers the catalog names, nothing more.
 */
export function createRunnerApp(runner: LabRunner, token: Buffer, logger: Logger, environments?: EnvironmentController) {
  const app = express();
  app.disable('x-powered-by');
  const expected = digest(`Bearer ${token.toString('base64')}`);

  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok' });
  });

  app.use((req: Request, res: Response, next: NextFunction) => {
    // Compare digests: constant time, and equal lengths whatever was sent.
    if (!timingSafeEqual(digest(req.headers.authorization ?? ''), expected)) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
    next();
  });
  app.use(express.json({ limit: '2kb' }));

  app.post('/instances', async (req, res) => {
    const parsed = startSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }
    try {
      res.status(201).json(await runner.start(parsed.data));
    } catch (err) {
      if (err instanceof LabImageMissing) res.status(503).json({ error: 'lab_image_missing' });
      else if (err instanceof LabAlreadyRunning) res.status(409).json({ error: 'already_running' });
      else {
        logger.error({ err }, 'lab start failed');
        res.status(502).json({ error: 'lab_start_failed' });
      }
    }
  });

  app.delete('/instances/:id', async (req, res) => {
    if (!INSTANCE_ID.test(req.params.id)) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }
    try {
      await runner.stop(req.params.id);
      res.status(204).end();
    } catch (err) {
      logger.error({ err }, 'lab stop failed');
      res.status(502).json({ error: 'lab_stop_failed' });
    }
  });

  if (environments) {
    const envId = (req: Request, res: Response) => {
      const parsed = environmentSchema.safeParse(req.params);
      if (!parsed.success) res.status(404).json({ error: 'not_found' });
      return parsed.success ? parsed.data.id : undefined;
    };
    const fail = (res: Response, err: unknown, step: string) => {
      if (err instanceof EnvironmentMissing) res.status(503).json({ error: 'environment_missing' });
      else {
        logger.error({ err }, `environment ${step} failed`);
        res.status(502).json({ error: 'environment_failed' });
      }
    };
    app.get('/environments/:id', async (req, res) => {
      const id = envId(req, res);
      if (!id) return;
      try {
        res.json(await environments.status(id));
      } catch (err) {
        fail(res, err, 'status');
      }
    });
    app.post('/environments/:id/start', async (req, res) => {
      const id = envId(req, res);
      if (!id) return;
      try {
        res.status(202).json(await environments.start(id));
      } catch (err) {
        fail(res, err, 'start');
      }
    });
    app.post('/environments/:id/stop', async (req, res) => {
      const id = envId(req, res);
      if (!id) return;
      try {
        await environments.stop(id);
        res.status(204).end();
      } catch (err) {
        fail(res, err, 'stop');
      }
    });
  }

  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'not_found' });
  });
  // Malformed JSON and the like: generic answer, nothing echoed.
  app.use((_err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    res.status(400).json({ error: 'invalid_request' });
  });
  return app;
}
