import { containerName, labLimits, LABS, type LabId } from '../catalog.js';

const MiB = 1024 * 1024;

/** Labels let the runner find its own objects again (TTL reaper), and only those. */
export const LABEL = 'bastion.lab';
export const LABEL_INSTANCE = 'bastion.lab.instance';
export const LABEL_EXPIRES = 'bastion.lab.expires';

/**
 * One network per instance, with no route out (`Internal`): a compromised lab
 * cannot download tools, call back to a C2, exfiltrate, or reach another
 * learner's lab. Only the gateway is attached to it besides the lab.
 */
export function networkSpec(instanceId: string, expiresAt: number) {
  return {
    Name: containerName(instanceId),
    Driver: 'bridge',
    Internal: true,
    Labels: { [LABEL]: '1', [LABEL_INSTANCE]: instanceId, [LABEL_EXPIRES]: String(expiresAt) },
  };
}

/**
 * The application inside is vulnerable on purpose; the container is not.
 * Every line below removes something an attacker who gets code execution in the
 * lab would use to go further.
 */
export function containerSpec(lab: LabId, instanceId: string, flag: string, expiresAt: number, runtime?: string) {
  const net = containerName(instanceId);
  const limits = labLimits(lab);
  return {
    Image: LABS[lab].image,
    // The learner's own flag, and nothing else from the platform.
    Env: [`FLAG=${flag}`],
    User: '65532:65532',
    Hostname: 'lab',
    Labels: { [LABEL]: '1', [LABEL_INSTANCE]: instanceId, [LABEL_EXPIRES]: String(expiresAt), 'bastion.lab.id': lab },
    HostConfig: {
      NetworkMode: net,
      // No port is published: the only way in is the gateway, on the instance network.
      PortBindings: {},
      Privileged: false,
      ReadonlyRootfs: true,
      CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges:true'],
      Tmpfs: { '/tmp': 'rw,noexec,nosuid,nodev,size=16m' },
      Memory: limits.memoryMiB * MiB,
      MemorySwap: limits.memoryMiB * MiB,
      NanoCpus: Math.round(limits.cpus * 1e9),
      PidsLimit: limits.pids,
      Ulimits: [{ Name: 'nofile', Soft: 1024, Hard: 1024 }],
      LogConfig: { Type: 'json-file', Config: { 'max-size': '1m', 'max-file': '1' } },
      RestartPolicy: { Name: 'no' },
      // A stronger sandbox (e.g. gVisor "runsc") when the host provides one.
      ...(runtime ? { Runtime: runtime } : {}),
    },
    NetworkingConfig: { EndpointsConfig: { [net]: {} } },
  };
}
