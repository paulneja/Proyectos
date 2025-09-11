import psutil
import tkinter as tk
from tkinter import ttk
import subprocess
import time

# Función para obtener GPU NVIDIA si existe
def get_gpu_usage():
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            usage = result.stdout.strip().split(", ")
            return f"{usage[0]}%  |  {usage[1]}MB / {usage[2]}MB  |  {usage[3]}°C"
    except Exception:
        pass
    return "No disponible"

# Monitor GUI
class MonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor de Sistema")
        self.root.configure(bg="black")
        self.root.geometry("600x500")  # más grande

        # Estilo de barras (neón)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Green.Horizontal.TProgressbar",
                        troughcolor="gray15", background="lime green")
        style.configure("Yellow.Horizontal.TProgressbar",
                        troughcolor="gray15", background="yellow")
        style.configure("Red.Horizontal.TProgressbar",
                        troughcolor="gray15", background="red")

        self.labels = {}
        self.bars = {}

        font_title = ("Consolas", 14, "bold")
        font_text = ("Consolas", 12)

        # CPU
        self.labels["cpu"] = tk.Label(root, text="CPU", fg="lime", bg="black", font=font_title)
        self.labels["cpu"].pack(pady=5)
        self.cpu_bar = ttk.Progressbar(root, length=500, style="Green.Horizontal.TProgressbar")
        self.cpu_bar.pack(pady=5)

        # RAM
        self.labels["ram"] = tk.Label(root, text="RAM", fg="cyan", bg="black", font=font_title)
        self.labels["ram"].pack(pady=5)
        self.ram_bar = ttk.Progressbar(root, length=500, style="Green.Horizontal.TProgressbar")
        self.ram_bar.pack(pady=5)

        # Disco
        self.labels["disk"] = tk.Label(root, text="Disco", fg="magenta", bg="black", font=font_title)
        self.labels["disk"].pack(pady=5)
        self.disk_bar = ttk.Progressbar(root, length=500, style="Green.Horizontal.TProgressbar")
        self.disk_bar.pack(pady=5)

        # Red
        self.labels["net"] = tk.Label(root, text="Red", fg="white", bg="black", font=font_text)
        self.labels["net"].pack(pady=10)

        # GPU
        self.labels["gpu"] = tk.Label(root, text="GPU", fg="white", bg="black", font=font_text)
        self.labels["gpu"].pack(pady=10)

        # Temperaturas
        self.labels["temps"] = tk.Label(root, text="Temperaturas", fg="white", bg="black", font=font_text)
        self.labels["temps"].pack(pady=10)

        self.update_monitor()

    def set_bar_style(self, bar, value):
        """Cambia el color de la barra según el valor"""
        if value < 50:
            bar.config(style="Green.Horizontal.TProgressbar")
        elif value < 80:
            bar.config(style="Yellow.Horizontal.TProgressbar")
        else:
            bar.config(style="Red.Horizontal.TProgressbar")

    def update_monitor(self):
        # CPU
        cpu = psutil.cpu_percent()
        self.cpu_bar["value"] = cpu
        self.set_bar_style(self.cpu_bar, cpu)
        self.labels["cpu"].config(text=f"CPU: {cpu}%", fg="lime")

        # RAM
        mem = psutil.virtual_memory()
        self.ram_bar["value"] = mem.percent
        self.set_bar_style(self.ram_bar, mem.percent)
        self.labels["ram"].config(
            text=f"RAM: {mem.used // (1024**2)} MB / {mem.total // (1024**2)} MB ({mem.percent}%)", fg="cyan"
        )

        # Disco
        disk = psutil.disk_usage('/')
        self.disk_bar["value"] = disk.percent
        self.set_bar_style(self.disk_bar, disk.percent)
        self.labels["disk"].config(
            text=f"Disco: {disk.used // (1024**3)} GB / {disk.total // (1024**3)} GB ({disk.percent}%)", fg="magenta"
        )

        # Red (velocidad instantánea)
        net1 = psutil.net_io_counters()
        time.sleep(0.5)
        net2 = psutil.net_io_counters()
        sent_speed = (net2.bytes_sent - net1.bytes_sent) / 1024 / 0.5
        recv_speed = (net2.bytes_recv - net1.bytes_recv) / 1024 / 0.5
        self.labels["net"].config(text=f"Red: ↑ {sent_speed:.1f} KB/s | ↓ {recv_speed:.1f} KB/s", fg="white")

        # GPU
        self.labels["gpu"].config(text=f"GPU: {get_gpu_usage()}", fg="white")

        # Temperaturas (si están disponibles)
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
            self.labels["temps"].config(text="Temperaturas:\n" + " | ".join(temp_info), fg="white")
        else:
            self.labels["temps"].config(text="Temperaturas: No disponible", fg="white")

        self.root.after(1000, self.update_monitor)

# Ejecutar GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = MonitorGUI(root)
    root.mainloop()
