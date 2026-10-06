import json
import os
import signal
import socket
import sys
import time

_SENSITIVE = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL")


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "report"
    if mode == "report":
        secret_present = any(any(part in key.upper() for part in _SENSITIVE) for key in os.environ)
        sys.stdout.write(
            json.dumps(
                {
                    "argv": sys.argv,
                    "env_keys": sorted(os.environ),
                    "path": os.environ.get("PATH"),
                    "home": os.environ.get("HOME"),
                    "secret_present": secret_present,
                }
            )
        )
        return 0
    if mode == "sleep":
        time.sleep(float(sys.argv[2]))
        print("awake")
        return 0
    if mode == "trap-sleep":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(float(sys.argv[2]))
        print("awake")
        return 0
    if mode == "flood":
        remaining = int(sys.argv[2])
        chunk = b"A" * 65536
        while remaining:
            take = min(remaining, len(chunk))
            sys.stdout.buffer.write(chunk[:take])
            remaining -= take
        sys.stdout.buffer.flush()
        return 0
    if mode == "spawn-sleep":
        seconds = float(sys.argv[2])
        pid = os.fork()
        if pid == 0:
            time.sleep(seconds)
            os._exit(0)
        sys.stdout.write(f"{pid}\n")
        sys.stdout.flush()
        os.waitpid(pid, 0)
        return 0
    if mode == "connect":
        host, port = sys.argv[2], int(sys.argv[3])
        sock = socket.socket()
        sock.settimeout(2)
        try:
            sock.connect((host, port))
        except OSError as exc:
            print(f"blocked {exc.errno}")
            return 0
        print("connected")
        return 0
    if mode == "marker":
        with open(sys.argv[2], "w", encoding="utf-8") as handle:
            handle.write("ran")
        print("marked")
        return 0
    if mode == "fail":
        print("nope", file=sys.stderr)
        return 7
    print("unknown", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
