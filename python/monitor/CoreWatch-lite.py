
import psutil
import time
import os
import subprocess
from rich.console import Console
from rich.table import Table

console = Console()

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_gpu_usage():
    """Devuelve uso de GPU, memoria y temperatura si hay NVIDIA."""
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            usage = result.stdout.strip().split(", ")
            return f"{usage[0]}% | {usage[1]}MB / {usage[2]}MB | {usage[3]}°C"
    except Exception:
        pass
    return "No disponible"

def get_network_speed(old, new, interval):
    """Calcula velocidad de red en KB/s."""
    sent_speed = (new.bytes_sent - old.bytes_sent) / 1024 / interval
    recv_speed = (new.bytes_recv - old.bytes_recv) / 1024 / interval
    return f"↑ {sent_speed:.1f} KB/s | ↓ {recv_speed:.1f} KB/s"

def colorize(value, thresholds=(50, 80)):
    """Devuelve color según porcentaje de uso."""
    if value < thresholds[0]:
        return f"[green]{value}%[/green]"
    elif value < thresholds[1]:
        return f"[yellow]{value}%[/yellow]"
    else:
        return f"[red]{value}%[/red]"

def show_monitor():
    old_net = psutil.net_io_counters()
    while True:
        clear()
        table = Table(title="[bold cyan]Monitor de Sistema[/bold cyan]", style="bold green")

        # CPU
        cpu_percent = psutil.cpu_percent(percpu=True)
        cpu_display = " | ".join([f"Core {i}: {colorize(p)}" for i, p in enumerate(cpu_percent)])
        table.add_row("[bold green]CPU[/bold green]", cpu_display)

        # CPU Temperatura (si está disponible)
        temp_info = []
        if hasattr(psutil, "sensors_temperatures"):
            try:
                temps = psutil.sensors_temperatures()
                for name, entries in temps.items():
                    for entry in entries:
                        temp_info.append(f"{name}: {entry.current}°C")
            except Exception:
                pass
        if temp_info:
            table.add_row("[bold green]Temp CPU[/bold green]", " | ".join(temp_info))
        else:
            table.add_row("[bold green]Temp CPU[/bold green]", "No disponible")

        # RAM
        mem = psutil.virtual_memory()
        ram_percent = mem.percent
        ram_info = f"{mem.used // (1024**2)} MB / {mem.total // (1024**2)} MB ({colorize(ram_percent)})"
        table.add_row("[bold green]RAM[/bold green]", ram_info)

        # Disco
        disk = psutil.disk_usage('/')
        disk_info = f"{disk.used // (1024**3)} GB / {disk.total // (1024**3)} GB ({colorize(disk.percent)})"
        table.add_row("[bold green]Disco[/bold green]", disk_info)

        # Red (velocidad en tiempo real)
        new_net = psutil.net_io_counters()
        net_info = get_network_speed(old_net, new_net, 1)
        old_net = new_net
        table.add_row("[bold green]Red[/bold green]", net_info)

        # GPU (si hay NVIDIA)
        gpu_info = get_gpu_usage()
        table.add_row("[bold green]GPU[/bold green]", gpu_info)

        console.print(table)
        time.sleep(1)

if __name__ == "__main__":
    show_monitor()
