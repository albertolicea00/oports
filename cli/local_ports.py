"""Read local TCP listeners without elevated privileges."""

import subprocess


def get_local_ports():
    try:
        result = subprocess.run(
            ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows = []
    pid = name = ""
    for line in result.stdout.splitlines():
        if line.startswith("p"):
            pid = line[1:]
            name = ""
        elif line.startswith("c"):
            name = line[1:]
        elif line.startswith("n") and pid:
            address = line[1:]
            port = address.rsplit(":", 1)[-1]
            if port.isdigit():
                rows.append({"pid": int(pid), "process": name, "address": address, "port": int(port)})
    return sorted(rows, key=lambda row: (row["port"], row["pid"], row["address"]))


def format_local_ports(rows):
    if not rows:
        return "No listening TCP ports found (or lsof is unavailable)."
    lines = ["PORT   PID      PROCESS              ADDRESS"]
    for row in rows:
        lines.append("{:<6} {:<8} {:<20} {}".format(row["port"], row["pid"], row["process"][:20], row["address"]))
    return "\n".join(lines)
