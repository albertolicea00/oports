"""Limited fallback for POSIX systems outside macOS."""

from .macos import (get_active_interfaces, get_active_connections, get_arp_table,
                    get_computer_name, get_default_gateway, get_lease_servers,
                    get_local_ports, ping_command)
