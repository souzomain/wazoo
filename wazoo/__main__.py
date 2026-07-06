import uvloop
import config
import argparse
import atexit
import logging
import multiprocessing
import os
import signal
import sys
from server import WazuhServer
from log import WazooLog
from pathlib import Path

def getFileContentIfExists(file_path: str) -> str | None:
    file = Path(file_path)
    if file.exists() and file.is_file():
        return file.read_text('utf-8')
    return None

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-rp",
        "--registration-port",
        type=int,
        default=1515,
        help="Registration server. default(1515)",
    )

    parser.add_argument(
        "-lp",
        "--logging-port",
        type=int,
        default=1514,
        help="Logging server. default(1514)",
    )

    parser.add_argument(
        "-p",
        "--password",
        type=str,
        help="Agent password enrolment or Agent password file like authd.pass. default(None)",
    )

    parser.add_argument(
        "--host", type=str, default="0.0.0.0", help="Host binding. default(0.0.0.0)"
    )

    parser.add_argument(
        "--ssl",
        default="./ssl",
        help="ssl path. It search for the files key.pem and cert.pem inside the path. default(./ssl)",
    )

    parser.add_argument(
        "--version", default="4.14.5", help="Wazuh server version. default(4.14.5)"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Add verbosity. default(False)",
    )

    parser.add_argument(
        "--name", type=str, default="manager", help="Manager name. default(manager)"
    )

    parser.add_argument(
        "--db", type=str, default="agents.db", help="Agents database. default(agents.db)"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=os.cpu_count(),
        help=f"Workers for decoding. default({os.cpu_count()})",
    )

    parser.add_argument(
        '--processes',
        type=int,
        default=1,
        help='Allow Multiprocessing reusing connection with reusing port. default(1)'
    )

    parser.add_argument(
        "-b",
        "--background",
        action="store_true",
        default=False,
        help="Detach and run in the background; PID written to --pid-file. default(False)",
    )

    parser.add_argument(
        "--pid-file",
        type=str,
        default="wazoo.pid",
        help="PID file path used with --background. default(wazoo.pid)",
    )

    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=None,
        help="Path to a YAML config file; values there override these defaults",
    )

    parser.add_argument(
        '-ck',
        '--client-keys',
        type=str,
        default='client.keys',
        help='Wazuh client keys file'
    )

    return parser.parse_args()


def build_server(args) -> WazuhServer:
    log = None
    if getattr(args, "log", None):
        log = WazooLog(
            args.log,
            option=args.log["option"],
            add_new_line=args.log.get("add_new_line", True),
            prefix=args.log.get("prefix", ""),
        )
    time_flush = 1
    line_flush = -1

    if getattr(args, 'buffer', None):
        time_flush = args.buffer.get('time_flush', 1)
        line_flush = args.buffer.get('line_flush', -1)

    if args.password:
        if Path(args.password).exists():
            args.password = getFileContentIfExists(args.password)

    return WazuhServer(
        host=args.host,
        port_registration=args.registration_port,
        port_logging=args.logging_port,
        password=args.password,
        client_keys=args.client_keys,
        ssl_path=Path(args.ssl),
        version=args.version,
        manager_name=args.name,
        db_path=args.db,
        reuse_port=args.workers > 1,
        log=log,
        workers=args.workers,
        max_time_flush=time_flush,
        max_line_flush=line_flush,
    )


def run_worker(args):
    config.configureLogging(args.verbose, console=not args.background)
    uvloop.run(build_server(args).start())


def daemonize(pid_file: str):
    sys.stdout.flush()
    sys.stderr.flush()
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    os.close(devnull)
    Path(pid_file).write_text(str(os.getpid()))
    atexit.register(lambda: Path(pid_file).unlink(missing_ok=True))


def main():
    args = parse_args()

    if args.config:
        args = argparse.Namespace(**config.load_config(args.config, **vars(args)))

    if args.background:
        print(f"Starting in background (pid file: {args.pid_file})")
        daemonize(args.pid_file)

    config.configureLogging(args.verbose, console=not args.background)

    if args.processes <= 1:
        uvloop.run(build_server(args).start())
        return

    build_server(args)

    ctx = multiprocessing.get_context("spawn")

    workers = [
        ctx.Process(
            target=run_worker, args=(args,), name=f"wazoo-worker-{i}", daemon=True
        )
        for i in range(args.processes)
    ]
    for worker in workers:
        worker.start()
    logging.info("Started %d worker processes", len(workers))

    def _handle_sigterm(*_):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_sigterm)
    try:
        for worker in workers:
            worker.join()
    except KeyboardInterrupt:
        pass
    finally:
        for worker in workers:
            worker.terminate()
        for worker in workers:
            worker.join(timeout=5)
            if worker.is_alive():
                worker.kill()


if __name__ == "__main__":
    main()
