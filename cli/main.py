"""Command line entry point shared by the installed command and local script."""

import argparse
import ipaddress
import json
import sys

try:
    from .scanner import inspect_host, scan_network
    from .formatter import format_device_table, format_host_inspection, print_banner
except ImportError:  # Direct execution from cli/oports
    from scanner import inspect_host, scan_network
    from formatter import format_device_table, format_host_inspection, print_banner


def main(argv=None):
    parser = argparse.ArgumentParser(prog="oports", description="Local network scanner and inspector")
    parser.add_argument("subcommand", nargs="?", choices=["ips", "local"])
    parser.add_argument("--ips", action="store_true", help="Print the LAN device table and exit")
    parser.add_argument("--local", action="store_true", help="Print listening local TCP ports and exit")
    parser.add_argument("--tui", action="store_true", help="Open the interactive dashboard")
    parser.add_argument("--inspect", metavar="IP", help="Inspect one IPv4 host in detail")
    parser.add_argument("--verbose", action="store_true", help="Show detailed reports for discovered hosts")
    parser.add_argument("-i", "--interface", help="Network interface to scan")
    parser.add_argument("--json", action="store_true", help="Print structured JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args(argv)

    modes = sum(bool(mode) for mode in (args.ips or args.subcommand == "ips", args.local or args.subcommand == "local", args.inspect, args.tui))
    if modes > 1:
        parser.error("choose one of --ips, --local, --inspect, or --tui")
    if args.verbose and not (args.ips or args.subcommand == "ips"):
        parser.error("--verbose requires --ips")
    if args.inspect:
        try:
            ipaddress.IPv4Address(args.inspect)
        except ValueError:
            parser.error("--inspect needs a valid IPv4 address")
        data = inspect_host(args.inspect)
        print(json.dumps(data, indent=2) if args.json else format_host_inspection(data, sys.stdout.isatty() and not args.no_color))
        return 0
    if args.local or args.subcommand == "local":
        try:
            from .local_ports import get_local_ports, format_local_ports
        except ImportError:
            from local_ports import get_local_ports, format_local_ports
        rows = get_local_ports()
        print(json.dumps(rows, indent=2) if args.json else format_local_ports(rows))
        return 0
    if args.tui or not (args.ips or args.subcommand == "ips" or args.json):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            parser.error("the dashboard needs a terminal; use --ips or --local for output")
        try:
            from .tui.app import OPortsApp
        except ModuleNotFoundError as exc:
            if exc.name == "textual":
                parser.error("Textual is required for the dashboard: pip install 'oports[tui]'")
            raise
        OPortsApp(interface=args.interface).run()
        return 0

    use_color = sys.stdout.isatty() and not args.no_color
    if not args.json:
        print_banner(use_color)
        print("\nScanning local network...\n")
    try:
        devices, subnet = scan_network(args.interface)
    except ValueError as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps({"subnet": subnet, "total_devices": len(devices), "devices": devices}, indent=2, ensure_ascii=False))
    else:
        print(format_device_table(devices, subnet, use_color))
        print("\nTotal active devices: {}".format(len(devices)))
        if args.verbose:
            for device in devices:
                print("\n" + format_host_inspection(inspect_host(device["ip"]), use_color))
    return 0
