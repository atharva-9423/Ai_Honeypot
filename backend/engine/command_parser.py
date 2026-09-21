"""Deterministic command parser. NEVER executes host commands. Simulation only."""
from __future__ import annotations
import posixpath
import shlex


def parse_and_execute(raw: str, session) -> dict:
    """Returns {output, accessed_paths, clear, exit}."""
    text = (raw or "").strip()
    if not text:
        return {"output": "", "accessed_paths": [], "clear": False, "exit": False}
    try:
        parts = shlex.split(text, posix=True)
    except ValueError:
        parts = text.split()
    if not parts:
        return {"output": "", "accessed_paths": [], "clear": False, "exit": False}
    cmd, args = parts[0], parts[1:]
    fs = session.fs
    accessed: list[str] = []

    def out(s: str = ""):
        return {"output": s, "accessed_paths": accessed, "clear": False, "exit": False}

    # --- help ---
    if cmd == "help":
        return out("Available commands:\n  help pwd ls cd cat mkdir touch echo whoami id uname ps history find grep env clear exit\n  ifconfig ip netstat hostname\n\nType /help for the attack command reference.")
    if cmd == "pwd":
        return out(session.cwd)
    if cmd == "whoami":
        return out("sentinel")
    if cmd == "id":
        return out("uid=1000(sentinel) gid=1000(sentinel) groups=1000(sentinel)")
    if cmd == "hostname":
        return out("server01")
    if cmd == "uname":
        if args and args[0] == "-a":
            return out("Linux server01 5.15.0-generic #1 SMP x86_64 GNU/Linux (synthetic)")
        return out("Linux")
    if cmd == "ps":
        return out("  PID TTY          TIME CMD\n  812 pts/0    00:00:00 bash\n  901 pts/0    00:00:00 app\n 1204 pts/0    00:00:00 ps")
    if cmd == "env":
        return out("\n".join(f"{k}={v}" for k, v in session.env.items()))
    if cmd == "history":
        lines = [f"  {i+1}  {c}" for i, c in enumerate(session.history)]
        return out("\n".join(lines) if lines else "")
    if cmd == "clear":
        return {"output": "", "accessed_paths": [], "clear": True, "exit": False}
    if cmd == "exit":
        return {"output": "logout", "accessed_paths": [], "clear": False, "exit": True}
    # --- network simulations (synthetic) ---
    if cmd == "ifconfig":
        return out("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.8  netmask 255.255.255.0 (SYNTHETIC)")
    if cmd == "ip":
        return out("1: lo: <LOOPBACK,UP> mtu 65536\n2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 (SYNTHETIC)\n    inet 10.0.0.8/24")
    if cmd == "netstat":
        return out("Active connections (synthetic):\n  tcp  0  0 10.0.0.8:8080  0.0.0.0:*  LISTEN\n  tcp  0  0 10.0.0.8:22    0.0.0.0:*  LISTEN")
    # --- ls ---
    if cmd == "ls":
        target = session.cwd
        show_hidden = False
        for a in args:
            if a.startswith("-"):
                if "a" in a:
                    show_hidden = True
            else:
                target = fs.resolve(session.cwd, a)
        try:
            children = fs.list_dir(target)
        except FileNotFoundError as e:
            return out(str(e))
        except NotADirectoryError:
            # ls on a file prints its name
            return out(posixpath.basename(target))
        names = sorted(children)
        if not show_hidden:
            names = [n for n in names if not n.startswith(".")]
        return out("  ".join(names) if names else "")
    # --- cd ---
    if cmd == "cd":
        dest = args[0] if args else "/home/sentinel"
        if dest == "-":
            dest = session.prev_dir
        resolved = fs.resolve(session.cwd, dest)
        if fs.is_dir(resolved):
            session.prev_dir = session.cwd
            session.cwd = resolved
            return out("")
        if fs.is_file(resolved):
            return out(f"bash: cd: {dest}: Not a directory")
        return out(f"bash: cd: {dest}: No such file or directory")
    # --- cat ---
    if cmd == "cat":
        if not args:
            return out("cat: missing operand")
        outs = []
        for a in args:
            if a.startswith("-"):
                continue
            p = fs.resolve(session.cwd, a)
            accessed.append(p)
            try:
                outs.append(fs.read_file(p))
            except IsADirectoryError as e:
                outs.append(str(e))
            except FileNotFoundError as e:
                outs.append(str(e))
        return out("\n".join(outs))
    # --- mkdir ---
    if cmd == "mkdir":
        if not args:
            return out("mkdir: missing operand")
        for a in args:
            if a.startswith("-"):
                continue
            try:
                fs.mkdir(fs.resolve(session.cwd, a))
            except (FileExistsError, NotADirectoryError, FileNotFoundError) as e:
                return out(str(e))
        return out("")
    # --- touch ---
    if cmd == "touch":
        if not args:
            return out("touch: missing file operand")
        for a in args:
            try:
                fs.touch(fs.resolve(session.cwd, a))
            except (FileNotFoundError, IsADirectoryError) as e:
                return out(str(e))
        return out("")
    # --- echo (supports > and >>) ---
    if cmd == "echo":
        if ">" in parts:
            idx = parts.index(">")
            append = False
            if idx > 0 and parts[idx - 1].endswith(">"):
                pass
            target_idx = idx + 1
            redir = ">"
            if idx + 1 < len(parts) and parts[idx] == ">":
                pass
            # handle >> as two tokens
            full = text
            if ">>" in full:
                segs = full.split(">>", 1)
                append = True
                content = segs[0].strip()[4:].strip().strip("'\"")
                target = segs[1].strip().split()[0] if segs[1].strip() else ""
            else:
                segs = full.split(">", 1)
                content = segs[0].strip()[4:].strip().strip("'\"")
                target = segs[1].strip().split()[0] if segs[1].strip() else ""
            if not target:
                return out("bash: syntax error near unexpected token `newline'")
            p = fs.resolve(session.cwd, target)
            try:
                existing = fs.read_file(p) if (fs.is_file(p) and append) else ""
                fs.write_file(p, (existing + content + "\n") if append else (content + "\n"))
                accessed.append(p)
            except FileNotFoundError as e:
                return out(str(e))
            return out("")
        # plain echo: strip leading 'echo '
        content = text[4:].strip() if len(text) > 4 else ""
        if (content.startswith('"') and content.endswith('"')) or \
           (content.startswith("'") and content.endswith("'")):
            content = content[1:-1]
        return out(content)
    # --- find ---
    if cmd == "find":
        base = session.cwd
        pattern = None
        rest = list(args)
        if rest and not rest[0].startswith("-"):
            base = fs.resolve(session.cwd, rest.pop(0))
        if "-name" in rest:
            i = rest.index("-name")
            if i + 1 < len(rest):
                pattern = rest[i + 1]
        if not fs.exists(base):
            return out(f"find: '{base}': No such file or directory")
        accessed.append(base)
        results = fs.find(base, pattern)
        return out("\n".join(results))
    # --- grep ---
    if cmd == "grep":
        if not args:
            return out("grep: missing operand")
        pat = None
        paths = []
        skip = False
        for i, a in enumerate(args):
            if a.startswith("-"):
                continue
            if pat is None:
                pat = a
            else:
                paths.append(a)
        if pat is None:
            return out("grep: missing pattern")
        pat_low = pat.lower().strip("'\"")
        if not paths:
            paths = [session.cwd]
        hits = []
        for pth in paths:
            p = fs.resolve(session.cwd, pth)
            accessed.append(p)
            targets = []
            if fs.is_file(p):
                targets = [p]
            elif fs.is_dir(p):
                targets = [f for f in fs.files if f == p or f.startswith(p.rstrip("/") + "/")]
            else:
                hits.append(f"grep: {pth}: No such file or directory")
                continue
            for t in sorted(targets):
                try:
                    content = fs.read_file(t)
                except Exception:
                    continue
                for line in content.splitlines():
                    if pat_low in line.lower():
                        hits.append(f"{t}:{line}")
        return out("\n".join(hits) if hits else "")
    if cmd in ("sudo", "su"):
        return out(f"{cmd}: permission denied (simulated)")
    if cmd == "crontab":
        if args and args[0] not in ("-l", "-r"):
            return out(f"crontab: installing new crontab for sentinel (simulated)")
        return out("no crontab for sentinel (simulated)")
    if cmd == "systemctl":
        sub = args[0] if args else ""
        target = args[1] if len(args) > 1 else "meridian-api"
        if sub == "status":
            return out(f"* {target}.service - Meridian service (simulated)\n"
                        f"   Loaded: loaded (/etc/systemd/system/{target}.service)\n"
                        "   Active: active (running)")
        if sub in ("enable", "disable", "start", "stop", "restart"):
            return out(f"{sub} {target} (simulated)")
        return out("systemctl: valid operations are status/enable/start/stop (simulated)")
    if cmd in ("ssh", "scp", "curl", "wget", "nmap", "nc"):
        return out(f"{cmd}: network access is disabled in this controlled environment (simulated)")
    if cmd == "chmod":
        return out("")
    if cmd == "chown":
        return out("chown: Operation not permitted (simulated)")
    return out(f"{cmd}: command not found")
