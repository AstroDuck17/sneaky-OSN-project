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
    storage_dir1 = tempdir / "storage1"
    storage_dir2 = tempdir / "storage2"
    storage_dir1.mkdir(parents=True, exist_ok=True)
    storage_dir2.mkdir(parents=True, exist_ok=True)

    nm_proc = subprocess.Popen(
        [str(BIN_NM), "5000", str(state_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    ss1_proc = None
    ss2_proc = None
    try:
        time.sleep(0.2)
        ss1_proc = subprocess.Popen(
            [
                str(BIN_SS),
                "ss1",
                "127.0.0.1",
                "6000",
                "127.0.0.1",
                "5000",
                str(storage_dir1),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        ss2_proc = subprocess.Popen(
            [
                str(BIN_SS),
                "ss2",
                "127.0.0.1",
                "6001",
                "127.0.0.1",
                "5000",
                str(storage_dir2),
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

                operations = [
                    "This is a test sentence.",
                    " Another sentence follows.",
                    " Final sentence to wrap up.",
                ]
                expected_text = "This is a test sentence. Another sentence follows. Final sentence to wrap up."
                inserted = 0
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
                    for chunk in operations:
                        send_json(
                            ss_sock,
                            {
                                "type": "WRITE_INSERT",
                                "index": inserted,
                                "content": chunk,
                            },
                        )
                        resp_ss = recv_json(ss_sock)
                        if resp_ss.get("status") != "OK":
                            print("WRITE_INSERT failed", resp_ss, file=sys.stderr)
                            return 1
                        inserted += len(chunk.strip().split())
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
                primary_server = resp.get("server")
                if primary_server != "ss1":
                    print("Unexpected primary server", resp, file=sys.stderr)
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
                    if resp_ss.get("status") != "OK" or resp_ss.get("content") != expected_text:
                        print("READ failed", resp_ss, file=sys.stderr)
                        return 1

                send_json(nm_sock, {"type": "INFO", "file": "doc.txt"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK" or resp.get("file", {}).get("name") != "doc.txt":
                    print("INFO failed", resp, file=sys.stderr)
                    return 1
                file_meta = resp.get("file", {})
                if file_meta.get("primaryServer") != "ss1" or file_meta.get("backupServer") != "ss2":
                    print("INFO server mismatch before failover", resp, file=sys.stderr)
                    return 1

                send_json(nm_sock, {"type": "STREAM", "file": "doc.txt"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("STREAM lookup failed", resp, file=sys.stderr)
                    return 1
                host, port, ticket = resp["host"], resp["port"], resp["ticket"]
                streamed_words = []
                with closing(socket.create_connection((host, int(port)))) as ss_sock:
                    send_json(
                        ss_sock,
                        {
                            "type": "STREAM",
                            "file": "doc.txt",
                            "user": "alice",
                            "ticket": ticket,
                        },
                    )
                    header = recv_json(ss_sock)
                    if header.get("status") != "OK":
                        print("STREAM start failed", header, file=sys.stderr)
                        return 1
                    while True:
                        chunk = recv_json(ss_sock)
                        if chunk.get("status") == "DONE":
                            break
                        if chunk.get("status") == "DATA" and "word" in chunk:
                            streamed_words.append(chunk["word"])
                if streamed_words != expected_text.split():
                    print("STREAM output mismatch", streamed_words, file=sys.stderr)
                    return 1

                ss1_proc.terminate()
                try:
                    ss1_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    ss1_proc.kill()
                ss1_proc = None
                time.sleep(0.2)

                send_json(nm_sock, {"type": "READ", "file": "doc.txt"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("READ lookup failed after failover", resp, file=sys.stderr)
                    return 1
                if resp.get("server") != "ss2":
                    print("Expected backup server after failover", resp, file=sys.stderr)
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
                    if resp_ss.get("status") != "OK" or resp_ss.get("content") != expected_text:
                        print("READ after failover failed", resp_ss, file=sys.stderr)
                        return 1

                send_json(nm_sock, {"type": "INFO", "file": "doc.txt"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK" or resp.get("file", {}).get("name") != "doc.txt":
                    print("INFO failed", resp, file=sys.stderr)
                    return 1
                file_meta = resp.get("file", {})
                if file_meta.get("primaryServer") != "ss2" or file_meta.get("backupServer") != "ss1":
                    print("INFO server mismatch after failover", resp, file=sys.stderr)
                    return 1

                send_json(nm_sock, {"type": "DELETE", "file": "doc.txt"})
                resp = recv_json(nm_sock)
                if resp.get("status") != "OK":
                    print("DELETE failed", resp, file=sys.stderr)
                    return 1
                if (storage_dir1 / "files" / "doc.txt").exists() or (
                    storage_dir2 / "files" / "doc.txt"
                ).exists():
                    print("File still exists on storage directories", file=sys.stderr)
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
            for proc in (ss1_proc, ss2_proc):
                if proc:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()

    finally:
        nm_proc.terminate()
        try:
            nm_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            nm_proc.kill()
        shutil.rmtree(tempdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_test())
