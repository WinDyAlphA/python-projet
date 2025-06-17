import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Iterable
import os


def _is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if *port* on *ip* is open, otherwise False."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return result == 0


def scan_ports(ip: str, ports: Iterable[int] | None = None, workers: int = 200) -> List[int]:
    """Scan *ip* for open *ports*.

    Parameters
    ----------
    ip : str
        IP address or hostname to scan.
    ports : Iterable[int] | None
        Ports to scan. If *None*, scans the well-known range 1-1024.
    workers : int
        Number of concurrent threads to use while scanning.

    Returns
    -------
    List[int]
        Sorted list of open ports.
    """
    if ports is None:
        ports = range(1, 8888)

    open_ports: List[int] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Launch tasks
        future_to_port = {executor.submit(_is_port_open, ip, port): port for port in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                # Ignore individual port errors to keep scanning
                pass

    return sorted(open_ports)


def _format_port_list(ports: List[int]) -> str:
    """Return a human-readable representation of *ports*."""
    if not ports:
        return "Aucun port ouvert détecté."
    return ", ".join(str(p) for p in ports)


def load_ports_from_file(file_path: str) -> List[int]:
    """Load comma-separated port numbers from *file_path*."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            # Split by comma, ignore empty parts, and cast to int
            return [int(p) for p in content.split(",") if p]
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Fichier de ports introuvable: {file_path}") from exc


def scan_main(ip):
    target_ip = ip

    # Path to the CSV file containing the 10k most popular TCP ports
    csv_file = os.path.join(os.path.dirname(__file__), "top-10000-most-popular-tcp-ports-nmap-sorted.csv")

    print(f"[*] Chargement des ports depuis {os.path.basename(csv_file)}…")
    ports_to_scan = load_ports_from_file(csv_file)
    print(f"[*] {len(ports_to_scan)} ports chargés. Démarrage du scan sur {target_ip}…")

    open_ports = scan_ports(target_ip, ports_to_scan)

    print("[+] Ports ouverts:", _format_port_list(open_ports))


if __name__ == "__main__":
    scan_main("127.0.0.1")
