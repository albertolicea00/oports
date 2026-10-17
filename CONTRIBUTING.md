# Contributing to OPorts

Thank you for your interest in contributing to **OPorts**!

## How to Contribute

1. **Fork the Repository**: Create your personal fork on GitHub.
2. **Clone your fork**:
   ```bash
   git clone https://github.com/<your-username>/OPorts.git
   cd OPorts
   ```
3. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```
4. **Make your changes**: Write clean, readable code and verify it locally.
5. **Test your changes**:
   ```bash
   ./cli/oports --ips
   ./cli/oports --ips --json
   ```
6. **Commit and Push**:
   ```bash
   git commit -m "Add: support for custom port profiling"
   git push origin feature/my-new-feature
   ```
7. **Open a Pull Request**: Submit your PR on GitHub with a clear description of the improvements.

## Code Style

- Keep external dependencies to zero or standard library where possible.
- Ensure cross-platform compatibility where feasible.
- Preserve clean ANSI terminal formatting.
