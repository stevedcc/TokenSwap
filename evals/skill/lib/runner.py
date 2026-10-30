"""The skill eval runner (evals/skill/run.sh is the entry point; see its header for usage).

Each scenario runs in its own bubblewrap sandbox: /usr read-only, a fresh HOME, the scenario folder
(/work) and /tmp as the only writable places besides the shims' state, and tswap, sudo, su, doas and
pkexec bind-mounted over by the eval shim wherever they exist. Before the agent starts, an isolation
check runs in the same sandbox and the run aborts unless every one of those names resolves to the
shim and no real tswap is reachable. The shims log through a Unix socket to a logger outside the
sandbox that accepts records only from the shim itself (LogServer), into a file bound read-only;
the judge (judge.py) reads that log, scans the files, and judges `says` rules with
a different model.
"""
import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import socket
import struct
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL_ROOT = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(EVAL_ROOT))
sys.path.insert(0, HERE)
import fake_agent  # noqa: E402
import judge  # noqa: E402

SHIMMED = ["tswap", "sudo", "su", "doas", "pkexec"]   # must resolve to the shim (isolation check)
# Logged (with whether a file they read holds a marker value), then the real one runs.
READERS = ["cat", "jq", "base64", "head", "tail", "grep", "sed", "awk", "less", "more", "strings", "xxd", "od"]


def passthrough_names():
    """{name: real binary} for each reader on this host, plus a symlink's target name (awk -> gawk):
    a bind over a symlink lands on its target, so the target's name must pass through too."""
    names = {}
    for name in READERS:
        real = shutil.which(name, path="/usr/bin:/bin")
        if real:
            names[name] = os.path.realpath(real)
            names.setdefault(os.path.basename(os.path.realpath(real)), os.path.realpath(real))
    return names


PASSTHROUGH = list(passthrough_names())
CANNED = ["kubectl", "helm", "psql"]                  # logged, canned answers
SYSTEM_DIRS = ["/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/usr/sbin"]
SANDBOX_HOME = "/home/eval"
ISOLATION_FAILED = 2


def parse_args(argv):
    p = argparse.ArgumentParser(prog="evals/skill/run.sh", description="Repeatable eval of the tswap skill.")
    p.add_argument("--agent", required=True, choices=["claude", "opencode", "fake"])
    p.add_argument("--model", help="the agent's model id (required for claude and opencode)")
    p.add_argument("--skill", required=True, choices=["on", "off"])
    p.add_argument("--scenario", help="run only this scenario (file name without .json)")
    p.add_argument("--agent-home", help="folder with the agent's login only, copied into the sandbox's fresh HOME")
    p.add_argument("--fake-variant", default="pass", help="fake agent only: a variant name, or 'all'")
    p.add_argument("--fake-script", help="fake agent only: run this bash script as the agent (variant 'script'; tests)")
    p.add_argument("--judge-agent", choices=["claude", "opencode"], help="CLI for the LLM judge of `says` rules")
    p.add_argument("--judge-model", help="model of the LLM judge; must differ from --model")
    p.add_argument("--tswap", help="the tswap binary whose `tswap prompt` is the skill (default: this repo's Debug build)")
    p.add_argument("--pass-env", action="append", default=[], help="environment variable to pass into the sandbox (repeatable)")
    p.add_argument("--timeout", type=int, default=900, help="seconds per scenario run (default 900)")
    p.add_argument("--keep", action="store_true", help="keep the run folders (printed at the end)")
    args = p.parse_args(argv)
    if args.agent != "fake":
        if not args.model:
            p.error("--model is required for claude and opencode")
        if args.fake_variant != "pass" or args.fake_script:
            p.error("--fake-variant and --fake-script are for --agent fake only")
    if args.judge_model and args.model and args.judge_model == args.model:
        p.error("the LLM judge must be a different model from the agent (--judge-model == --model)")
    if bool(args.judge_model) != bool(args.judge_agent):
        p.error("--judge-agent and --judge-model go together")
    return args


def load_scenarios(name):
    folder = os.path.join(EVAL_ROOT, "scenarios")
    files = sorted(f for f in os.listdir(folder) if f.endswith(".json"))
    if name:
        files = [f for f in files if f[:-5] == name]
        if not files:
            sys.exit(f"run.sh: no scenario '{name}' in {folder}")
    scenarios = []
    for f in files:
        with open(os.path.join(folder, f)) as fh:
            scenario = json.load(fh)
        if not scenario.get("rules", {}).get("must"):
            sys.exit(f"run.sh: scenario {f} has no `must` rule (an agent that does nothing would pass)")
        scenarios.append(scenario)
    return scenarios


def skill_text(args):
    if args.skill == "off":
        return None
    tswap = args.tswap or os.path.join(REPO_ROOT, "TswapCli", "bin", "Debug", "net10.0", "linux-x64", "tswap")
    if not os.path.isfile(tswap):
        sys.exit(f"run.sh: --skill on needs a built tswap for `tswap prompt` ({tswap} not found; build it or pass --tswap)")
    env = {k: v for k, v in os.environ.items() if not k.startswith("TSWAP_")}
    out = subprocess.run([tswap, "prompt"], capture_output=True, text=True, env=env)
    if out.returncode != 0:
        sys.exit(f"run.sh: `{tswap} prompt` failed: {out.stderr.strip()}")
    return out.stdout


def host_tswap_paths():
    """Where the host has tswap binaries (PATH, the usual folders): none may be reachable in the sandbox."""
    paths = set()
    for d in os.environ.get("PATH", "").split(":") + SYSTEM_DIRS + [os.path.expanduser("~/.local/bin")]:
        candidate = os.path.join(d, "tswap") if d else None
        if candidate and os.path.exists(candidate):
            paths.add(os.path.abspath(candidate))
            paths.add(os.path.realpath(candidate))
    return sorted(paths)


class LogServer:
    """
    The shims' logger, outside the sandbox: a Unix socket bound into it at /eval/log.sock. A record
    is accepted only when the sending process (SO_PEERCRED, its pid in this pid namespace) is the
    system Python running one of the read-only shim paths (/proc/<pid>/exe and /proc/<pid>/cmdline);
    anything else is dropped and counted as forged, which fails the scenario. The shim waits for the
    answer, so the process is still there to be checked. There is no stop message: the runner closes
    the socket itself.
    """

    PYTHON = "/usr/bin/python3"

    def __init__(self, sock_path, log_path, shim_paths):
        self.log_path, self.shim_paths = log_path, set(shim_paths)
        self.python_exe = os.path.realpath(self.PYTHON)
        self.forged = 0
        self.lock = threading.Lock()
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(sock_path)
        os.chmod(sock_path, 0o600)
        self.server.listen(64)
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def genuine(self, pid):
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = f.read().split(b"\0")
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            return False
        if exe != self.python_exe or len(argv) < 3 or argv[0] != self.PYTHON.encode() or argv[1] != b"-I":
            return False
        script = argv[2].decode(errors="replace")
        if not script.startswith("/"):
            script = os.path.join(cwd, script)  # both are paths inside the sandbox
        return os.path.normpath(script) in self.shim_paths

    def _handle(self, conn):
        with conn:
            try:
                conn.settimeout(10)
                pid, _uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                # Checked when the connection is accepted and again after the record is read: a
                # process that connects as something else and only then execs the shim fails the
                # first check, unless it wins the race to exec before the accept (README.md).
                at_accept = self.genuine(pid)
                data = b""
                while not data.endswith(b"\n") and len(data) < 1 << 20:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                ok = at_accept and data.endswith(b"\n") and data.count(b"\n") == 1 and self.genuine(pid)
                with self.lock:
                    if ok:
                        with open(self.log_path, "ab") as log:
                            log.write(data)
                    else:
                        self.forged += 1
                conn.sendall(b"1" if ok else b"0")
            except OSError:
                pass

    def stop(self):
        try:
            self.server.shutdown(socket.SHUT_RDWR)  # wakes the blocked accept(); close() alone doesn't
        except OSError:
            pass
        self.server.close()
        self.thread.join(timeout=10)


def prepare(run_dir, scenario, skill, agent_home, agent_script):
    """The host folders of one run: work (the scenario folder), home, tmp, and eval (bound at /eval)."""
    work, home, tmp, ev = (os.path.join(run_dir, d) for d in ("work", "home", "tmp", "eval"))
    for d in (work, home, tmp, ev):
        os.makedirs(d)
    for rel, content in scenario.get("files", {}).items():
        path = os.path.join(work, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    if agent_home:
        shutil.copytree(agent_home, home, dirs_exist_ok=True, symlinks=True)
    os.makedirs(os.path.join(ev, "shims"))
    shutil.copy(os.path.join(EVAL_ROOT, "shims", "shim.py"), os.path.join(ev, "shims", "shim.py"))
    os.chmod(os.path.join(ev, "shims", "shim.py"), 0o755)
    os.makedirs(os.path.join(ev, "bin"))
    for name in SHIMMED + PASSTHROUGH + CANNED:
        os.symlink("/eval/shims/shim.py", os.path.join(ev, "bin", name))
    os.makedirs(os.path.join(ev, "real"))
    for name in PASSTHROUGH:
        open(os.path.join(ev, "real", name), "w").close()  # mount points
    os.makedirs(os.path.join(ev, "lib"))
    shutil.copy(os.path.join(HERE, "isolation_check.sh"), os.path.join(ev, "lib", "isolation_check.sh"))
    os.makedirs(os.path.join(ev, "state"))
    with open(os.path.join(ev, "state", "vault.json"), "w") as f:
        json.dump({"secrets": {n: dict({"version": 1}, **s) for n, s in scenario.get("vault", {}).items()}}, f)
    # What the shims need, without the rules (the agent can read /eval).
    with open(os.path.join(ev, "scenario.json"), "w") as f:
        json.dump({"kubernetes": scenario.get("kubernetes", {}), "marker_names": scenario.get("marker_names", [])}, f)
    with open(os.path.join(ev, "prompt.md"), "w") as f:
        f.write(skill or "")
    if agent_script is not None:
        with open(os.path.join(ev, "agent.sh"), "w") as f:
            f.write(agent_script)
    open(os.path.join(run_dir, "log.jsonl"), "w").close()
    open(os.path.join(ev, "log.jsonl"), "w").close()  # mount point of the log, bound read-only
    return work, home, tmp, ev


def bwrap_args(run_dir, work, home, tmp, ev, args, extra_path):
    a = ["bwrap", "--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--unshare-ipc",
         "--unshare-uts", "--unshare-cgroup-try", "--proc", "/proc", "--dev", "/dev",
         # The agent is root in its user namespace: with CAP_SYS_ADMIN it could unmount the shims,
         # with CAP_SYS_CHROOT/CAP_MKNOD build its own root. No capabilities at all (bwrap's
         # unprivileged default, made explicit; the isolation check verifies it).
         "--cap-drop", "ALL",
         "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc"]
    for top in ("/bin", "/sbin", "/lib", "/lib64", "/lib32"):
        if os.path.islink(top):
            a += ["--symlink", os.readlink(top), top]
        elif os.path.isdir(top):
            a += ["--ro-bind", top, top]
    a += ["--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve"]
    a += ["--bind", tmp, "/tmp", "--bind", home, SANDBOX_HOME, "--bind", work, "/work",
          "--ro-bind", ev, "/eval", "--bind", os.path.join(ev, "state"), "/eval/state",
          "--bind", os.path.join(ev, "log.sock"), "/eval/log.sock",
          "--ro-bind", os.path.join(run_dir, "log.jsonl"), "/eval/log.jsonl"]
    for extra in extra_path:
        a += ["--ro-bind", extra, extra]
    for name, real in passthrough_names().items():
        a += ["--ro-bind", real, f"/eval/real/{name}"]
    # The shim over every existing copy of a shimmed name, in the system folders (deduplicated by
    # real folder: /bin and /sbin are links into /usr on most systems) and in the fresh HOME.
    # shim_paths: every path inside the sandbox at which the shim runs (the logger accepts records
    # only from these), including /bin/x for a shim bound over /usr/bin/x when /bin links there.
    seen = set()
    shim = os.path.join(ev, "shims", "shim.py")
    shim_paths = {f"/eval/bin/{name}" for name in SHIMMED + PASSTHROUGH + CANNED}
    for name in SHIMMED + PASSTHROUGH + CANNED:
        for d in SYSTEM_DIRS:
            path = os.path.join(os.path.realpath(d), name)
            if os.path.islink(path):
                # bwrap can't mount on a symlink: the shim goes over its target (also in the name
                # list, e.g. gawk for awk), and the link itself runs the shim through it.
                if os.path.dirname(os.path.realpath(path)) == os.path.dirname(path):
                    shim_paths.update(os.path.join(dd, name) for dd in SYSTEM_DIRS
                                      if os.path.realpath(dd) == os.path.dirname(path))
                continue
            if path not in seen and os.path.lexists(path) and not os.path.isdir(path):
                seen.add(path)
                a += ["--ro-bind", shim, path]
        for path in seen:
            if os.path.basename(path) == name:
                shim_paths.update(os.path.join(d, name) for d in SYSTEM_DIRS
                                  if os.path.realpath(d) == os.path.dirname(path))
        if os.path.lexists(os.path.join(home, ".local", "bin", name)):
            a += ["--ro-bind", shim, f"{SANDBOX_HOME}/.local/bin/{name}"]
            shim_paths.add(f"{SANDBOX_HOME}/.local/bin/{name}")
    # Test hook (tests only): extra read-only binds, to prove the isolation check aborts.
    for pair in filter(None, os.environ.get("EVAL_TEST_EXTRA_RO_BIND", "").split(",")):
        src, dest = pair.split(":", 1)
        a += ["--ro-bind", src, dest]
    path = ":".join(["/eval/bin", "/usr/local/bin", "/usr/bin", "/bin"] + extra_path)
    env = {"HOME": SANDBOX_HOME, "PATH": path, "TERM": "dumb", "LANG": "C.UTF-8", "USER": "eval", "TMPDIR": "/tmp",
           "EVAL_HOST_TSWAP_PATHS": ":".join(host_tswap_paths())}
    for name in args.pass_env:
        if name in os.environ:
            env[name] = os.environ[name]
    a += ["--clearenv"]
    for k, v in env.items():
        a += ["--setenv", k, v]
    a += ["--chdir", "/work"]
    return a, shim_paths


def agent_command(args, scenario, skill, work):
    if args.agent == "fake":
        return ["/bin/bash", "/eval/agent.sh"], []
    binary = shutil.which(args.agent)
    if not binary:
        sys.exit(f"run.sh: '{args.agent}' is not on PATH")
    real = os.path.realpath(binary)
    extra_path = [os.path.dirname(real)]
    if args.agent == "claude":
        cmd = [real, "-p", scenario["task"], "--model", args.model, "--output-format", "text",
               "--dangerously-skip-permissions"]
        if skill:
            cmd += ["--append-system-prompt", skill]
    else:
        cmd = [real, "run", "--model", args.model, scenario["task"]]
        if skill:
            with open(os.path.join(work, "AGENTS.md"), "w") as f:
                f.write(skill)
    return cmd, extra_path


def run_one(args, scenario, variant, script, skill, base):
    run_dir = os.path.join(base, f"{scenario['name']}-{variant}")
    os.makedirs(run_dir)
    work, home, tmp, ev = prepare(run_dir, scenario, skill, args.agent_home, script)
    command, extra_path = agent_command(args, scenario, skill, work)
    logger = LogServer(os.path.join(ev, "log.sock"), os.path.join(run_dir, "log.jsonl"), set())
    sandbox, logger.shim_paths = bwrap_args(run_dir, work, home, tmp, ev, args, extra_path)
    try:
        check = subprocess.run(sandbox + ["/bin/bash", "/eval/lib/isolation_check.sh"], capture_output=True, text=True, timeout=60)
        if check.returncode != 0:
            return None, (check.stdout + check.stderr).strip()
        try:
            result = subprocess.run(sandbox + command, capture_output=True, text=True, timeout=args.timeout)
            message, stderr, timed_out = result.stdout, result.stderr, False
        except subprocess.TimeoutExpired as ex:
            message = ex.stdout.decode(errors="replace") if isinstance(ex.stdout, bytes) else (ex.stdout or "")
            stderr, timed_out = "", True
    finally:
        logger.stop()
    with open(os.path.join(run_dir, "final.txt"), "w") as f:
        f.write(message)
    with open(os.path.join(run_dir, "agent.stderr"), "w") as f:
        f.write(stderr)
    if args.agent == "fake":
        says_judge = judge.fake_judge
    elif args.judge_model:
        says_judge = judge.llm_judge(args.judge_agent, args.judge_model)
    else:
        says_judge = lambda rule, msg: (False, "not judged: no --judge-agent/--judge-model given")  # noqa: E731
    broken, notes, _records = judge.judge_run(scenario, os.path.join(run_dir, "log.jsonl"), work, tmp, message, says_judge,
                                              forged=logger.forged, extra_roots=[home, os.path.join(ev, "state")], home=home)
    if timed_out:
        notes.append(f"timed out after {args.timeout}s")
    return broken, notes


def main(argv):
    args = parse_args(argv)
    if not sys.platform.startswith("linux"):
        sys.exit("run.sh: the skill eval runs on Linux only (it needs bubblewrap)")
    if not shutil.which("bwrap"):
        sys.exit("run.sh: bubblewrap (bwrap) is not installed")
    scenarios = load_scenarios(args.scenario)
    skill = skill_text(args)
    base = tempfile.mkdtemp(prefix="tswap-skill-eval-")
    passed = failed = 0
    try:
        for scenario in scenarios:
            if args.agent == "fake":
                all_variants = fake_agent.variants(scenario)
                if args.fake_script:
                    with open(args.fake_script) as f:
                        all_variants = {"script": (f.read(), [])}
                names = list(all_variants) if args.fake_variant == "all" or args.fake_script else [args.fake_variant]
                runs = []
                for n in names:
                    if n not in all_variants:
                        sys.exit(f"run.sh: scenario {scenario['name']} has no fake variant '{n}' (has: {', '.join(all_variants)})")
                    runs.append((n, all_variants[n][0], all_variants[n][1]))
            else:
                runs = [("agent", None, None)]
            for variant, script, expected in runs:
                label = scenario["name"] if variant == "agent" else f"{scenario['name']}/{variant}"
                broken, notes = run_one(args, scenario, variant, script, skill, base)
                if broken is None:
                    print(f"ABORT {label}: isolation check failed, the agent was not started\n{notes}")
                    return ISOLATION_FAILED
                expect = "" if args.agent != "fake" else f" (expected: {','.join(expected) or 'pass'})"
                suffix = ("  [" + "; ".join(notes) + "]") if notes else ""
                if broken:
                    failed += 1
                    ids = ",".join(b[0] for b in broken)
                    print(f"FAIL {label}: {broken[0][0]} {broken[0][1]} [broken: {ids}]{expect}{suffix}")
                else:
                    passed += 1
                    print(f"PASS {label}{expect}{suffix}")
                sys.stdout.flush()
    finally:
        if args.keep:
            print(f"run folders kept in {base}")
        else:
            shutil.rmtree(base, ignore_errors=True)
    print(f"summary: {passed + failed} run, {passed} passed, {failed} failed "
          f"(agent {args.agent}{' ' + args.model if args.model else ''}, skill {args.skill})")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
