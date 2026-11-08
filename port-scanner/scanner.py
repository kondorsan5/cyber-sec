import argparse
import csv
import json
import logging
import math
import socket
import time

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

def setup_logger(verbose=False, log_file="logs/scanner.log"):
    logger = logging.getLogger("port_scanner")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)sZ - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    formatter.converter = time.gmtime

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if not logger.handlers:

        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler(
            log_path,
            encoding="utf-8",
            mode="a"
        )

        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            handler.setLevel(
                logging.DEBUG if verbose else logging.INFO
            )

        elif isinstance(handler, logging.StreamHandler):
            handler.setLevel(
                logging.DEBUG if verbose else logging.INFO
            )

    return logger

def validate_port(value: int) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer")

    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")

    return port

def new_output(output_path):
    if output_path is None:
        output_path = Path("output/results.csv")
    else:
        output_path = Path(output_path)

    if output_path.suffix == "":
        output_path = output_path.with_suffix(".csv")

    elif output_path.suffix.lower() != ".csv":
        raise ValueError("Output file must have a .csv extension")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    return output_path

def validate_host(host: str) -> str:

    if not host or host != host.strip():
        raise argparse.ArgumentTypeError (
            f"Invalid hostname: cannot be empty or contain whitespace"
        )

    if "://" in host or "/" in host or ":" in host:
        raise argparse.ArgumentTypeError (
            f"Invalid hostname {host}: must not contain scheme or portname"
        )
    return host

def validate_timeout(value):
    try:
         timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid timeout value: must be a number")

    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("Invalid timeout value: must be finite or greater than zero")

    return timeout

def get_args(argv=None):

    parser = argparse.ArgumentParser(description="Port scanner for test purporses. Use only in a lab")
    parser.add_argument("host", type=validate_host)
    scan_group = parser.add_argument_group("Scanning")
    scan_group.add_argument("--start", type=validate_port, default=1, help="First port to scan. Accepts values between 1 and 65535. Cannot be higher than --end")
    scan_group.add_argument("--end", type=validate_port, default=1024, help="Last port to scan. Accepts values between 1 and 65535. Cannot be lower than --start")
    scan_group.add_argument("--timeout", type=validate_timeout, default=1.0, help="Timeout value for scanning ports. Accepts float value")
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("--output", type=Path, help="Provide a custom path for the report output")
    output_group.add_argument("--verbose", action="store_true", help="Choose verbosity of the log file. Adds DEBUG logs")

    args = parser.parse_args(argv)
    
    if args.start > args.end:
        parser.error("--start value needs cannot be higher than --end value")

    return args

def check_port(target_ip, port, timeout):
    logger = logging.getLogger("port_scanner")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))

            if result == 0:
                logger.info(f"Open port detected: {port}")
                return True

        logger.debug(
            f"Port {port} is closed or unavailable. Error code: {result}"
        )
        return False      

    except socket.gaierror as error:
        raise ValueError(
            f"Cannot resolve hostname: {target_ip}"
        ) from error

    except TimeoutError:
        logger.debug(f"Timeout while checking port {port}")
        return False

    except OSError as error:
        logger.error(f"Error checking port {port}: {error}")
        return False

def scan_ports(host, start_port, end_port, timeout):
    port_info_list = []

    logger = logging.getLogger("port_scanner")
    host_res = resolve_host(host)
    logger.info(f"{host} resolved to {host_res}")
    stats = Counter()
    for port in range(start_port, end_port + 1):
        stats["count"] += 1
        is_open = check_port(host_res, port, timeout)
        port_info = {
            "host": host,
            "port": port,
            "status": "open" if is_open else "unavailable",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if is_open:
            stats["open"] +=1
        else:
            stats["closed"] +=1

        port_info_list.append(port_info)

    return port_info_list, stats

def resolve_host(host: str):
    try:
        host_resolved = socket.gethostbyname(host)
        return host_resolved
    except socket.gaierror as error:
        raise ValueError(f"Cannot resolve hostname: {host}") from error

def output_csv(filename: Path, data : dict, fieldnames : list, logger):
    try:
        with open(filename, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)

    except (TypeError, ValueError, IsADirectoryError) as error:
           logger.error(f"Error saving CSV file: {error}")
           raise

def output_json(path, data):
    try:
        with open(path, 'w', encoding="utf-8") as file:
            json.dump(data, file)

    except (OSError, TypeError, ValueError, IsADirectoryError, json.JSONDecodeError) as error:
           print(f"Error saving JSON file: {error}")

def print_statistics(stat_report):
    print(f"Number of scanned  ports: {stat_report["count"]}")
    print(f"Number of open ports: {stat_report["open"]}")
    print(f"Number of closed ports: {stat_report["closed"]}")

def main(argv=None):
    args = get_args(argv)
    output_path = new_output(args.output)

    logger = setup_logger(args.verbose)

    logger.info("Starting scanner with user provided arguments")

    logger.info(f"Target host: {args.host}")
    logger.info(f"Port range: {args.start}-{args.end}")
    logger.info(f"Timeout: {args.timeout}s")

    logger.info(f"Output path created: {output_path}")

    try:
        logger.info("Host resolved properly")

        port_list, statistics_report = scan_ports(args.host, args.start, args.end, args.timeout)
        
        open_port_list = []
        for info in port_list:
            if info["status"] == "open":
                open_port_list.append(info)

        print_statistics(statistics_report)
        csv_fieldnames = ["host", "port", "status", "timestamp"]
        output_csv(output_path, open_port_list, csv_fieldnames, logger)
        output_json("output/results.json", port_list)
        logger.info(f"Scan completed, results saved to {output_path}",)
        
    except (ValueError, OSError) as error:
        logger.error(f"Scan failed: {error}")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
