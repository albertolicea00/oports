"""Entry point for building a tray-first standalone application."""

from interfaces.tray.app import tray_main


if __name__ == "__main__":
    raise SystemExit(tray_main())
