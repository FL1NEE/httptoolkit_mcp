import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const pexecFile = promisify(execFile);

/** Known emulator-bundled adb locations across the common Android emulators. */
const KNOWN_ADB_PATHS = [
  // Nox
  "C:/Program Files/Nox/bin/adb.exe",
  "C:/Program Files (x86)/Nox/bin/adb.exe",
  "C:/Program Files/Nox/bin/nox_adb.exe",
  "C:/Program Files (x86)/Nox/bin/nox_adb.exe",
  // MEmu
  "C:/Program Files/Microvirt/MEmu/adb.exe",
  "C:/Program Files/Microvirt/MEmuHyperv/adb.exe",
  // BlueStacks 5 (nxt) / older
  "C:/Program Files/BlueStacks_nxt/HD-Adb.exe",
  "C:/Program Files/BlueStacks_nxt/Engine/adb.exe",
  "C:/Program Files/BlueStacks/HD-Adb.exe",
  // LDPlayer
  "C:/LDPlayer/LDPlayer9/adb.exe",
  "C:/LDPlayer/LDPlayer4.0/adb.exe",
  "C:/Program Files/LDPlayer/LDPlayer9/adb.exe",
  // Genymotion
  "C:/Program Files/Genymobile/Genymotion/tools/adb.exe",
  // Android SDK (generic / AVD)
  "C:/Program Files (x86)/Android/android-sdk/platform-tools/adb.exe",
];

/**
 * Default `adb connect` targets per emulator. BlueStacks ports are dynamic
 * (read from bluestacks.conf, often 5555/5565/5575); 5555 is the usual first.
 */
export const EMULATOR_PRESETS: Record<string, { hostPort: string; note: string }> = {
  nox: { hostPort: "127.0.0.1:62001", note: "Nox (extra instances: 62025, 62026, ...)" },
  memu: { hostPort: "127.0.0.1:21503", note: "MEmu" },
  bluestacks: { hostPort: "127.0.0.1:5555", note: "BlueStacks 5 - enable ADB in Advanced settings; try 5565/5575 for extra instances" },
  ldplayer: { hostPort: "127.0.0.1:5555", note: "LDPlayer (extra instances: 5557, 5559, ...)" },
  genymotion: { hostPort: "", note: "Genymotion auto-registers with adb; use adb_devices" },
};

type RootMode = "direct" | "su";

export class Adb {
  private adbPath: string | undefined;
  private rootMode: RootMode | undefined;

  constructor(private readonly explicitPath?: string) {}

  /** Resolve the adb binary: explicit env path, a known location, or PATH. */
  async resolveAdb(): Promise<string> {
    if (this.adbPath) return this.adbPath;
    const candidates = [this.explicitPath, ...KNOWN_ADB_PATHS].filter(Boolean) as string[];
    for (const c of candidates) {
      try {
        await fs.access(c);
        this.adbPath = c;
        return c;
      } catch {
        /* try next */
      }
    }
    this.adbPath = "adb"; // fall back to PATH
    return this.adbPath;
  }

  private async run(args: string[]): Promise<{ stdout: string; stderr: string }> {
    const adb = await this.resolveAdb();
    try {
      const { stdout, stderr } = await pexecFile(adb, args, { maxBuffer: 32 * 1024 * 1024 });
      return { stdout, stderr };
    } catch (err: any) {
      const out = (err.stdout ?? "") + (err.stderr ?? err.message ?? "");
      throw new Error(`adb ${args.join(" ")} failed: ${out.trim()}`);
    }
  }

  private dev(serial: string | undefined, args: string[]): string[] {
    return serial ? ["-s", serial, ...args] : args;
  }

  async listDevices(): Promise<{ serial: string; state: string }[]> {
    const { stdout } = await this.run(["devices"]);
    return stdout
      .split(/\r?\n/)
      .slice(1)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("*"))
      .map((l) => {
        const [serial, state] = l.split(/\s+/);
        return { serial, state };
      });
  }

  /** Connect over TCP, accepting either a host:port or an emulator preset name. */
  async connect(target: string): Promise<string> {
    const preset = EMULATOR_PRESETS[target.toLowerCase()];
    const hostPort = preset?.hostPort || target;
    if (!hostPort) throw new Error(`No fixed port for "${target}" - use adb_devices instead.`);
    const { stdout, stderr } = await this.run(["connect", hostPort]);
    return (stdout + stderr).trim();
  }

  /**
   * Tunnel a device port back to the host over the adb channel
   * (device 127.0.0.1:remotePort -> host 127.0.0.1:hostPort). This is the
   * reliable way to reach the host from emulators behind their own NAT
   * (e.g. MEmu, where the gateway IP is the emulator's virtual router, not
   * the host), bypassing host firewall and NAT entirely.
   */
  async reverse(hostPort: number, remotePort = hostPort, serial?: string): Promise<void> {
    await this.run(this.dev(serial, ["reverse", `tcp:${remotePort}`, `tcp:${hostPort}`]));
  }

  async removeReverse(serial?: string): Promise<void> {
    await this.run(this.dev(serial, ["reverse", "--remove-all"])).catch(() => {});
  }

  /** Detect how to get a root shell: already-root adbd, or via `su`. */
  private async detectRoot(serial?: string): Promise<RootMode> {
    const id = await this.run(this.dev(serial, ["shell", "id", "-u"])).catch(() => ({ stdout: "" }));
    if (id.stdout.trim() === "0") return "direct";
    // Try to elevate adbd itself (works on Nox/MEmu and rooted dev images).
    try {
      await this.run(this.dev(serial, ["root"]));
      await new Promise((r) => setTimeout(r, 800));
      const id2 = await this.run(this.dev(serial, ["shell", "id", "-u"])).catch(() => ({ stdout: "" }));
      if (id2.stdout.trim() === "0") return "direct";
    } catch {
      /* ignore */
    }
    // Fall back to su (BlueStacks/LDPlayer with the Root toggle enabled).
    const su = await this.run(this.dev(serial, ["shell", "su", "-c", "id -u"])).catch(() => ({ stdout: "" }));
    if (su.stdout.trim() === "0") return "su";
    throw new Error(
      "Could not obtain root on the device. Enable Root in the emulator settings " +
        "(BlueStacks/LDPlayer) or use Nox/MEmu where adbd runs as root.",
    );
  }

  /** Cached root-mode detection. */
  private async root(serial?: string): Promise<RootMode> {
    if (!this.rootMode) this.rootMode = await this.detectRoot(serial);
    return this.rootMode;
  }

  /** Run a shell command as root (direct adbd root or via `su`). */
  private async rootRun(cmd: string, serial?: string): Promise<{ stdout: string; stderr: string }> {
    const mode = await this.root(serial);
    const args = mode === "su" ? ["shell", "su", "-c", cmd] : ["shell", cmd];
    return this.run(this.dev(serial, args));
  }

  private async runScript(scriptName: string, arg: string, mode: RootMode, serial?: string): Promise<string> {
    const remote = `/data/local/tmp/${scriptName}`;
    const cmd = `sh ${remote} ${arg}`;
    const args = mode === "su" ? ["shell", "su", "-c", cmd] : ["shell", cmd];
    const { stdout, stderr } = await this.run(this.dev(serial, args));
    return (stdout + stderr).trim();
  }

  /**
   * Install the proxy CA into the Android *system* trust store via adb.
   * Handles both writable-/system images (Nox/MEmu, Android <=9) and
   * read-only /system on Android 10+ (tmpfs overlay over cacerts).
   * System certs are trusted by all apps and invisible to user-store
   * anti-MITM checks. Hard-pinned apps are still unaffected.
   */
  async installSystemCert(
    caPemPath: string,
    serial?: string,
  ): Promise<{ hash: string; remotePath: string; method: string; log: string }> {
    const hash = await subjectHashOld(caPemPath);
    const remotePath = `/system/etc/security/cacerts/${hash}.0`;
    const mode = await this.root(serial);

    // Stage cert + install script on the device.
    const stagedCert = path.join(os.tmpdir(), `${hash}.0`);
    await fs.copyFile(caPemPath, stagedCert);
    const stagedScript = path.join(os.tmpdir(), "htk-install-cert.sh");
    await fs.writeFile(stagedScript, INSTALL_SCRIPT.replace(/\r\n/g, "\n"), "utf8");

    await this.run(this.dev(serial, ["push", stagedCert, `/data/local/tmp/${hash}.0`]));
    await this.run(this.dev(serial, ["push", stagedScript, "/data/local/tmp/htk-install-cert.sh"]));
    await fs.unlink(stagedCert).catch(() => {});
    await fs.unlink(stagedScript).catch(() => {});

    const out = await this.runScript("htk-install-cert.sh", hash, mode, serial);
    const method = out.includes("INSTALLED_APEX")
      ? "apex-overlay (Android 14)"
      : out.includes("INSTALLED_TMPFS")
        ? "tmpfs-overlay (Android 10-13)"
        : out.includes("INSTALLED_DIRECT")
          ? "system-write (Android 7-9)"
          : "unknown";
    if (method === "unknown" || !out.includes(`${hash}.0`)) {
      throw new Error(`Cert install may have failed. Device output:\n${out}`);
    }
    return { hash, remotePath, method, log: out };
  }

  // --- Transparent interception (iptables DNAT) --------------------------

  /**
   * Transparently redirect all device TCP :80/:443 to the proxy via iptables
   * DNAT. Captures every app's traffic with no companion app and no VPN
   * consent dialog - Mockttp identifies targets by Host header / TLS SNI.
   */
  async enableTransparent(hostPort: string, serial?: string): Promise<string> {
    const out: string[] = [];
    for (const dport of [80, 443]) {
      const r = await this.rootRun(
        `iptables -t nat -A OUTPUT -p tcp --dport ${dport} -j DNAT --to-destination ${hostPort}`,
        serial,
      );
      out.push(`:${dport} -> ${hostPort} ${(r.stdout + r.stderr).trim() || "ok"}`);
    }
    return out.join("\n");
  }

  async disableTransparent(hostPort: string, serial?: string): Promise<string> {
    const out: string[] = [];
    for (const dport of [80, 443]) {
      await this.rootRun(
        `iptables -t nat -D OUTPUT -p tcp --dport ${dport} -j DNAT --to-destination ${hostPort}`,
        serial,
      ).catch(() => {});
      out.push(`removed :${dport} -> ${hostPort}`);
    }
    return out.join("\n");
  }

  async transparentStatus(serial?: string): Promise<string> {
    const { stdout } = await this.rootRun("iptables -t nat -L OUTPUT -n", serial);
    return stdout.trim();
  }

  async isSystemCertInstalled(caPemPath: string, serial?: string): Promise<boolean> {
    const hash = await subjectHashOld(caPemPath);
    const { stdout } = await this.run(
      this.dev(serial, ["shell", "ls", `/system/etc/security/cacerts/${hash}.0`]),
    ).catch(() => ({ stdout: "" }));
    return stdout.includes(`${hash}.0`) && !stdout.toLowerCase().includes("no such");
  }

  async setProxy(hostPort: string, serial?: string): Promise<void> {
    await this.run(this.dev(serial, ["shell", "settings", "put", "global", "http_proxy", hostPort]));
  }

  async clearProxy(serial?: string): Promise<void> {
    await this.run(this.dev(serial, ["shell", "settings", "put", "global", "http_proxy", ":0"]));
    // Android mirrors the proxy into separate keys; leaving these set points
    // proxy-aware apps at a now-dead host and breaks their networking.
    const keys = [
      "http_proxy",
      "global_http_proxy_host",
      "global_http_proxy_port",
      "global_http_proxy_exclusion_list",
      "global_proxy_pac_url",
    ];
    for (const k of keys) {
      await this.run(this.dev(serial, ["shell", "settings", "delete", "global", k])).catch(() => {});
    }
  }

  async getProxy(serial?: string): Promise<string> {
    const { stdout } = await this.run(
      this.dev(serial, ["shell", "settings", "get", "global", "http_proxy"]),
    );
    return stdout.trim();
  }
}

/**
 * On-device installer. Tries a direct write to the system cacerts dir; if
 * /system is read-only (Android 10+), overlays a tmpfs copy of the existing
 * trust store plus our cert. Runs as root (direct adbd root or via `su`).
 */
const INSTALL_SCRIPT = `#!/system/bin/sh
HASH="$1"
SRC="/data/local/tmp/$HASH.0"
SYS="/system/etc/security/cacerts"
APEX="/apex/com.android.conscrypt/cacerts"

mount -o rw,remount / 2>/dev/null
mount -o rw,remount /system 2>/dev/null

# Approach 1 - directly writable /system, no APEX store (Android 7/9 images).
if [ ! -d "$APEX" ] && cp "$SRC" "$SYS/$HASH.0" 2>/dev/null; then
  chmod 644 "$SYS/$HASH.0"
  echo "INSTALLED_DIRECT"
  ls -l "$SYS/$HASH.0"
  exit 0
fi

# Build a full copy of the current trust store + our cert in a temp dir.
WORK=/data/local/tmp/htk-cacerts
rm -rf "$WORK"; mkdir -p "$WORK"
if [ -d "$APEX" ]; then cp "$APEX"/* "$WORK"/ 2>/dev/null; else cp "$SYS"/* "$WORK"/ 2>/dev/null; fi
cp "$SRC" "$WORK/$HASH.0"
chmod 644 "$WORK"/* 2>/dev/null
chown 0:0 "$WORK"/* 2>/dev/null

# Overlay a tmpfs copy onto a cacerts dir (used both directly and via nsenter).
apply() {
  D="$1"
  mount -t tmpfs tmpfs "$D" 2>/dev/null
  cp "$WORK"/* "$D"/ 2>/dev/null
  chown 0:0 "$D"/* 2>/dev/null
  chmod 644 "$D"/* 2>/dev/null
  chcon u:object_r:system_security_cacerts_file:s0 "$D"/* 2>/dev/null
  restorecon -R "$D" 2>/dev/null
}

# Apply in the current namespace.
apply "$SYS"
[ -d "$APEX" ] && apply "$APEX"

# Propagate into the init mount namespace so every zygote-forked app sees it
# (required on Android 10+; APEX store on Android 14).
if command -v nsenter >/dev/null 2>&1; then
  WORK="$WORK" SYS="$SYS" APEX="$APEX" nsenter --mount=/proc/1/ns/mnt -- sh -c '
    apply2() {
      D="$1"
      mount -t tmpfs tmpfs "$D" 2>/dev/null
      cp "$WORK"/* "$D"/ 2>/dev/null
      chown 0:0 "$D"/* 2>/dev/null
      chmod 644 "$D"/* 2>/dev/null
      chcon u:object_r:system_security_cacerts_file:s0 "$D"/* 2>/dev/null
      restorecon -R "$D" 2>/dev/null
    }
    apply2 "$SYS"
    [ -d "$APEX" ] && apply2 "$APEX"
  ' 2>/dev/null
fi

if [ -d "$APEX" ]; then echo "INSTALLED_APEX"; else echo "INSTALLED_TMPFS"; fi
ls -l "$SYS/$HASH.0"
`;

/**
 * Compute the OpenSSL subject_hash_old of a PEM cert - the filename Android's
 * system trust store expects (<hash>.0).
 */
export async function subjectHashOld(caPemPath: string): Promise<string> {
  try {
    const { stdout } = await pexecFile("openssl", [
      "x509",
      "-inform",
      "PEM",
      "-subject_hash_old",
      "-noout",
      "-in",
      caPemPath,
    ]);
    const hash = stdout.split(/\r?\n/)[0].trim();
    if (!/^[0-9a-f]{8}$/.test(hash)) {
      throw new Error(`unexpected openssl output: ${stdout.trim()}`);
    }
    return hash;
  } catch (err: any) {
    throw new Error(`Failed to compute subject_hash_old (is openssl installed?): ${err.message ?? err}`);
  }
}
