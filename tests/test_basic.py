#!/usr/bin/env python3

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
BIN_NM = REPO_ROOT / "bin" / "nm"
BIN_SS = REPO_ROOT / "bin" / "ss"


def send_json(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    header = len(data).to_bytes(4, "big")
    sock.sendall(header + data)


def recv_json(sock: socket.socket) -> dict:
    header = sock.recv(4)
    if len(header) < 4:
        raise RuntimeError("connection closed")
    size = int.from_bytes(header, "big")
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("connection closed during payload")
        data += chunk
    return json.loads(data.decode("utf-8"))


def wait_for_start(path: Path, timeout: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return True
        time.sleep(0.05)
    return path.exists()


def run_test() -> int:
    for binary in (BIN_NM, BIN_SS):
        if not binary.exists():
            print("Required binary missing. Run `make` first.", file=sys.stderr)
            return 2

    tempdir = Path(tempfile.mkdtemp(prefix="docspp-test-"))
    state_file = tempdir / "nm_state.db"
    storage_dir = tempdir / "storage"
    storage_dir.mkdir(parents=True, exist_ok=True)

    nm_proc = subprocess.Popen(
        [str(BIN_NM), "5000", str(state_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(0.2)
        ss_proc = subprocess.Popen(
            [
                str(BIN_SS),
                "ss1",
                "127.0.0.1",
                "6000",
                "127.0.0.1",
                "5000",
                str(storage_dir),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            time.sleep(0.3)
            with closing(socket.create_connection(("127.0.0.1", 5000))) as nm_sock:
                client_payload = {
                    "type": "CLIENT_HELLO",
                    "user": "alice",
                    "clientIp": "127.0.0.1",
                    "nmPort": "5000",
                    "ssPort": "0",
                }
                send_json(nm_sock, client_payload)
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("CLIENT_HELLO failed", resp, file=sys.stderr)
                    return 1

                time.sleep(0.3)

                for _ in range(10):
                    send_json(nm_sock, {"type": "CREATE", "file": "doc.txt"})
                    resp = recv_json(nm_sock)
                    if resp.get("status") == "OK":
                        break
                    if resp.get("code") == "ERR_UNAVAILABLE":
                        time.sleep(0.1)
                        continue
                    print("CREATE failed", resp, file=sys.stderr)
                    return 1
                else:
                    print("CREATE failed after retries", resp, file=sys.stderr)
                    return 1

                send_json(nm_sock, {"type": "WRITE", "file": "doc.txt", "sentence": 0})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("WRITE lookup failed", resp, file=sys.stderr)
                    return 1
                host, port, ticket = resp["host"], resp["port"], resp["ticket"]

                with closing(socket.create_connection((host, int(port)))) as ss_sock:
                    send_json(
                        ss_sock,
                        {
                            "type": "WRITE_BEGIN",
                            "file": "doc.txt",
                            "user": "alice",
                            "ticket": ticket,
                            "sentence": 0,
                        },
                    )
                    resp_ss = recv_json(ss_sock)
                    if resp_ss.get("status") != "OK":
                        print("WRITE_BEGIN failed", resp_ss, file=sys.stderr)
                        return 1
                    send_json(
                        ss_sock,
                        {
                            "type": "WRITE_INSERT",
                            "index": 0,
                            "content": "This is a test sentence.",
                        },
                    )
                    resp_ss = recv_json(ss_sock)
                    if resp_ss.get("status") != "OK":
                        print("WRITE_INSERT failed", resp_ss, file=sys.stderr)
                        return 1
                    send_json(ss_sock, {"type": "WRITE_COMMIT"})
                    resp_ss = recv_json(ss_sock)
                    if resp_ss.get("status") != "OK":
                        print("WRITE_COMMIT failed", resp_ss, file=sys.stderr)
                        return 1

                send_json(nm_sock, {"type": "READ", "file": "doc.txt"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("READ lookup failed", resp, file=sys.stderr)
                    return 1
                host, port, ticket = resp["host"], resp["port"], resp["ticket"]
                with closing(socket.create_connection((host, int(port)))) as ss_sock:
                    send_json(
                        ss_sock,
                        {
                            "type": "READ",
                            "file": "doc.txt",
                            "user": "alice",
                            "ticket": ticket,
                        },
                    )
                    resp_ss = recv_json(ss_sock)
                    if resp_ss.get("status") != "OK" or "This is a test sentence." not in resp_ss.get("content", ""):
                        print("READ failed", resp_ss, file=sys.stderr)
                        return 1

                send_json(nm_sock, {"type": "UNDO", "file": "doc.txt"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("UNDO failed", resp, file=sys.stderr)
                    return 1

                send_json(nm_sock, {"type": "READ", "file": "doc.txt"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("READ lookup failed after undo", resp, file=sys.stderr)
                    return 1
                host, port, ticket = resp["host"], resp["port"], resp["ticket"]
                with closing(socket.create_connection((host, int(port)))) as ss_sock:
                    send_json(
                        ss_sock,
                        {
                            "type": "READ",
                            "file": "doc.txt",
                            "user": "alice",
                            "ticket": ticket,
                        },
                    )
                    resp_ss = recv_json(ss_sock)
                    if resp_ss.get("status") != "OK" or resp_ss.get("content") not in ("", None):
                        print("READ after undo unexpected", resp_ss, file=sys.stderr)
                        return 1

                send_json(nm_sock, {"type": "LIST"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK" or "alice" not in resp.get("users", []):
                    print("LIST failed", resp, file=sys.stderr)
                    return 1

                send_json(nm_sock, {"type": "VIEW", "flags": "al"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("VIEW failed", resp, file=sys.stderr)
                    return 1

                # EXEC test: create script file and ensure output is returned
                send_json(nm_sock, {"type": "CREATE", "file": "script.sh"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("CREATE script failed", resp, file=sys.stderr)
                    return 1
                send_json(nm_sock, {"type": "WRITE", "file": "script.sh", "sentence": 0})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("WRITE lookup script failed", resp, file=sys.stderr)
                    return 1
                script_host, script_port, script_ticket = resp["host"], resp["port"], resp["ticket"]
                with closing(socket.create_connection((script_host, int(script_port)))) as ss_sock:
                    send_json(
                        ss_sock,
                        {
                            "type": "WRITE_BEGIN",
                            "file": "script.sh",
                            "user": "alice",
                            "ticket": script_ticket,
                            "sentence": 0,
                        },
                    )
                    resp_ss = recv_json(ss_sock)
                    if resp_ss.get("status") != "OK":
                        print("WRITE_BEGIN script failed", resp_ss, file=sys.stderr)
                        return 1
                    send_json(
                        ss_sock,
                        {"type": "WRITE_INSERT", "index": 0, "content": "echo EXEC_OK"},
                    )
                    resp_ss = recv_json(ss_sock)
                    if resp_ss.get("status") != "OK":
                        print("WRITE_INSERT script failed", resp_ss, file=sys.stderr)
                        return 1
                    send_json(ss_sock, {"type": "WRITE_COMMIT"})
                    resp_ss = recv_json(ss_sock)
                    if resp_ss.get("status") != "OK":
                        print("WRITE_COMMIT script failed", resp_ss, file=sys.stderr)
                        return 1

                send_json(nm_sock, {"type": "EXEC", "file": "script.sh"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK" or "EXEC_OK" not in resp.get("output", ""):
                    print("EXEC failed", resp, file=sys.stderr)
                    return 1

            return 0

        finally:
            ss_proc.terminate()
            try:
                ss_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ss_proc.kill()

    finally:
        nm_proc.terminate()
        try:
            nm_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            nm_proc.kill()
        shutil.rmtree(tempdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_test())
