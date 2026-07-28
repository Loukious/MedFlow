#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shlex
import shutil
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]


def discover_server(explicit: str = "") -> Path:
    candidates = [
        explicit,
        os.getenv("LLAMA_CPP_SERVER", ""),
        str(Path.home() / "llama.cpp" / "build" / "bin" / "llama-server"),
        shutil.which("llama-server") or "",
    ]
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if candidate and path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
    raise FileNotFoundError(
        "Could not find llama-server. Set LLAMA_CPP_SERVER or pass --server."
    )


def discover_model(explicit: str = "") -> Path:
    configured = explicit or os.getenv("LOCAL_QWEN_GGUF", "")
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path.resolve()
        raise FileNotFoundError(f"Configured Qwen GGUF does not exist: {path}")

    hf_home = Path(
        os.getenv("HF_HOME", str(Path.home() / ".cache" / "huggingface"))
    ).expanduser()
    candidates = [
        path
        for path in (hf_home / "hub").glob(
            "models--*Qwen*-GGUF/snapshots/*/*.gguf"
        )
        if path.is_file()
        and path.stat().st_size > 256 * 1024 * 1024
        and not path.name.lower().startswith("mmproj")
    ]
    if not candidates:
        raise FileNotFoundError(
            "Could not find a cached Qwen GGUF. Set LOCAL_QWEN_GGUF or pass --model."
        )

    q4_candidates = [path for path in candidates if "Q4_K" in path.name.upper()]
    pool = q4_candidates or candidates
    return max(pool, key=lambda path: path.stat().st_mtime).resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Launch the cached local Qwen model through llama.cpp."
    )
    parser.add_argument("--server", default="", help="Path to llama-server.")
    parser.add_argument("--model", default="", help="Path to a Qwen GGUF.")
    parser.add_argument("--alias", default="", help="Model name exposed by the API.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--ctx-size", type=int, default=8192)
    parser.add_argument("--gpu-layers", type=int, default=99)
    parser.add_argument("--parallel", type=int, default=1)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the resolved command without starting the server.",
    )
    return parser


def main() -> None:
    load_dotenv(ROOT / ".env")
    args = build_parser().parse_args()
    server = discover_server(args.server)
    model = discover_model(args.model)
    alias = args.alias or os.getenv("LOCAL_QWEN_MODEL", "qwen-local")
    command = [
        str(server),
        "--model",
        str(model),
        "--alias",
        alias,
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--ctx-size",
        str(args.ctx_size),
        "--n-gpu-layers",
        str(args.gpu_layers),
        "--flash-attn",
        "on",
        "--parallel",
        str(args.parallel),
        "--reasoning",
        "off",
    ]

    environment = os.environ.copy()
    wsl_cuda = Path("/usr/lib/wsl/lib")
    if wsl_cuda.is_dir():
        current = environment.get("LD_LIBRARY_PATH", "")
        paths = [item for item in current.split(":") if item]
        if str(wsl_cuda) not in paths:
            paths.insert(0, str(wsl_cuda))
        environment["LD_LIBRARY_PATH"] = ":".join(paths)

    print(f"llama.cpp: {server}")
    print(f"Qwen GGUF: {model}")
    print(f"Endpoint: http://{args.host}:{args.port}/v1")
    print(shlex.join(command), flush=True)
    if args.dry_run:
        return
    os.execvpe(command[0], command, environment)


if __name__ == "__main__":
    main()
