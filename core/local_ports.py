"""Read local TCP listeners without elevated privileges."""

import platforms


def get_local_ports():
    return platforms.get_local_ports()


def format_local_ports(rows):
    if not rows:
        return "No listening TCP ports found (or lsof is unavailable)."
    lines = ["PORT   PID      PROCESS              ADDRESS"]
    for row in rows:
        lines.append("{:<6} {:<8} {:<20} {}".format(row["port"], row["pid"], row["process"][:20], row["address"]))
    return "\n".join(lines)
