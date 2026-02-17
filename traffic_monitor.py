import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
import threading
import subprocess
import socket

import logging
import os


class Network:
    root: tk.Tk

    # Хранилища данных
    ip_bytes_dict: dict = {}  # IP -> Int (Сумма байт)
    ip_ports_dict: dict = {}  # IP -> Set (Множество уникальных портов)
    suspicious_ips: set = set()  # Множество подозрительных IP
    blocked_ips: set = set()  # Множество заблокированных IP
    is_active: bool = False

    # НАСТРОЙКИ ПРАВИЛ
    SIZE_THR: int = 10240  # Лимит трафика
    PORT_SCAN_THR: int = 5  # Лимит уникальных портов

    my_ip: str = ""

    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitor")
        self.root.geometry("1300x700")

        self.sniffer = None  # scapy.AsyncSniffer
        # чтобы не спамить логом на каждый пакет
        self._last_logged_reason = {}  # ip -> reason_str
        self._setup_logging()

        self.my_ips = self.get_local_ipv4_set()
        self.gateway_ip = self.detect_gateway_ip()
        logging.info(f"Local IPv4 list: {sorted(self.my_ips)}")
        logging.info(f"Default gateway: {self.gateway_ip if self.gateway_ip else 'N/A'}")

        # --- СТИЛИ ---
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="white", foreground="black", rowheight=25, fieldbackground="white",
                        font=('Helvetica', 10))
        style.configure("Treeview.Heading", font=('Helvetica', 10, 'bold'), background="#e1e1e1", relief="raised")

        root.grid_columnconfigure(0, weight=4)
        root.grid_columnconfigure(1, weight=3)
        root.grid_columnconfigure(2, weight=2)
        root.grid_rowconfigure(0, weight=1)

        # ==========================================
        # 1. ЛОГ ПАКЕТОВ (Packet Log)
        # ==========================================
        all_ips_frame = tk.Frame(root)
        all_ips_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        tk.Label(all_ips_frame, text="Packet Log", font=("Helvetica", 12, "bold")).pack(side="top", fill="x",
                                                                                        pady=(0, 5))

        table_container_1 = tk.Frame(all_ips_frame)
        table_container_1.pack(side="top", fill="both", expand=True)

        scroll_all = ttk.Scrollbar(table_container_1, orient="vertical")
        self.all_ips_table = ttk.Treeview(table_container_1, columns=("IP", "Port", "Size"),
                                          show="headings", yscrollcommand=scroll_all.set)
        scroll_all.config(command=self.all_ips_table.yview)
        scroll_all.pack(side="right", fill="y")
        self.all_ips_table.pack(side="left", fill="both", expand=True)

        self.all_ips_table.heading("IP", text="Source IP")
        self.all_ips_table.heading("Port", text="Port")
        self.all_ips_table.heading("Size", text="Size")
        self.all_ips_table.column("IP", width=120, anchor="center")
        self.all_ips_table.column("Port", width=60, anchor="center")
        self.all_ips_table.column("Size", width=80, anchor="center")

        btn_frame_1 = tk.Frame(all_ips_frame)
        btn_frame_1.pack(side="bottom", fill="x", pady=10)
        self.start_button = ttk.Button(btn_frame_1, text="Start Monitor", command=self.start_monitoring)
        self.start_button.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.stop_button = ttk.Button(btn_frame_1, text="Stop Monitor", command=self.stop_monitoring, state="disabled")
        self.stop_button.pack(side="left", fill="x", expand=True, padx=(5, 0))

        # ==========================================
        # 2. ПОДОЗРИТЕЛЬНЫЕ (Suspicious)
        # ==========================================
        suspicious_frame = tk.Frame(root)
        suspicious_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        label_text = f"Suspicious (>{self.SIZE_THR}B OR >{self.PORT_SCAN_THR} Ports)"
        tk.Label(suspicious_frame, text=label_text, font=("Helvetica", 12, "bold")).pack(side="top", fill="x",
                                                                                         pady=(0, 5))

        self.suspicious_table = ttk.Treeview(
            suspicious_frame,
            columns=("IP", "Reason", "Total", "Ports"),
            show="headings"
        )

        self.suspicious_table.heading("IP", text="IP Address")
        self.suspicious_table.heading("Reason", text="Reason")
        self.suspicious_table.heading("Total", text="Total (KB)")
        self.suspicious_table.heading("Ports", text="Ports")

        self.suspicious_table.column("IP", width=100, anchor="center")
        self.suspicious_table.column("Reason", width=130, anchor="center")
        self.suspicious_table.column("Total", width=80, anchor="center")
        self.suspicious_table.column("Ports", width=60, anchor="center")
        # +++

        self.suspicious_table.pack(side="top", fill="both", expand=True)

        self.block_button = ttk.Button(suspicious_frame, text="Block Selected IP",
                                       state="disabled", command=self.block_ip)
        self.block_button.pack(side="bottom", fill="x", pady=10)

        self.suspicious_table.bind("<<TreeviewSelect>>", self.on_suspicious_select)

        # ==========================================
        # 3. ЗАБЛОКИРОВАННЫЕ (Blocked)
        # ==========================================
        blocked_frame = tk.Frame(root)
        blocked_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")

        tk.Label(blocked_frame, text="Blocked", font=("Helvetica", 12, "bold")).pack(side="top", fill="x", pady=(0, 5))

        self.blocked_table = ttk.Treeview(blocked_frame, columns=("IP",), show="headings")
        self.blocked_table.heading("IP", text="IP Address")
        self.blocked_table.column("IP", anchor="center")
        self.blocked_table.pack(side="top", fill="both", expand=True)

        self.unblock_button = ttk.Button(blocked_frame, text="Unblock Selected IP",
                                         state="disabled", command=self.unblock_ip)
        self.unblock_button.pack(side="bottom", fill="x", pady=10)

        self.blocked_table.bind("<<TreeviewSelect>>", self.on_blocked_select)

    def _setup_logging(self):
        os.makedirs("logs", exist_ok=True)
        logging.basicConfig(
            filename="logs/network_monitor.log",
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )
        logging.info("App started")

    def get_local_ipv4_set(self):
        ips = {"127.0.0.1"} # lo
        try:
            out = subprocess.check_output(
                ["ip", "-4", "addr", "show"],
                text=True,
                stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    addr = line.split()[1]
                    ip = addr.split("/")[0]
                    ips.add(ip)
        except Exception as e:
            logging.warning(f"Failed to read local IPv4 list: {e}")
        return ips

    def detect_gateway_ip(self):
        try:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                text=True,
                stderr=subprocess.DEVNULL
            ).strip()
            if not out:
                return ""
            line = out.splitlines()[0]
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
        except Exception as e:
            logging.warning(f"Failed to detect default gateway: {e}")
        return ""

    def packet_callback(self, packet: scapy.Packet):
        if not self.monitoring_active:
            return

        if packet.haslayer(scapy.IP):            # проверка на наличие IPv4
            ip_address = packet[scapy.IP].src

            # не работаем со своими адресами, со шлюзом и с заблокированными
            if ip_address in self.my_ips:
                return

            if self.gateway_ip and ip_address == self.gateway_ip:
                return

            if ip_address in self.blocked_ips:
                return

            packet_size = len(packet)

            if ip_address not in self.ip_bytes_dict:
                self.ip_bytes_dict[ip_address] = 0
            self.ip_bytes_dict[ip_address] += packet_size

            # достаем порт
            dst_port = None
            if packet.haslayer(scapy.TCP):
                dst_port = packet[scapy.TCP].dport
            elif packet.haslayer(scapy.UDP):
                dst_port = packet[scapy.UDP].dport

            # докадываем порт к адресу
            if dst_port:
                if ip_address not in self.ip_ports_dict:
                    self.ip_ports_dict[ip_address] = set()
                self.ip_ports_dict[ip_address].add(dst_port)

            reasons = []

            current_bytes = self.ip_bytes_dict[ip_address]
            if current_bytes > self.SIZE_THR:
                reasons.append("Traffic Limit")

            unique_ports_count = len(self.ip_ports_dict.get(ip_address, []))
            if unique_ports_count > self.PORT_SCAN_THR:
                reasons.append("Port Scanning")

            if reasons:
                reason_str = ", ".join(reasons)
                kb_size = round(current_bytes / 1024, 1)
                kb_str = f"{kb_size} KB"
                ports_str = str(unique_ports_count)

                prev = self._last_logged_reason.get(ip_address)
                if prev != reason_str:
                    self._last_logged_reason[ip_address] = reason_str
                    logging.warning(
                        f"SUSPICIOUS ip={ip_address} reason={reason_str} bytes={current_bytes} ports={unique_ports_count}"
                    )

                if self.suspicious_table.exists(ip_address):
                    self.suspicious_table.set(ip_address, column="Total", value=kb_str)
                    self.suspicious_table.set(ip_address, column="Reason", value=reason_str)
                    self.suspicious_table.set(ip_address, column="Ports", value=ports_str)  # +++
                else:
                    self.suspicious_ips.add(ip_address)
                    # +++ добавили ports_str в values
                    self.suspicious_table.insert(
                        "", "end", iid=ip_address,
                        values=(ip_address, reason_str, kb_str, ports_str)
                    )

                self.sort_suspicious_table()

            size_str = f"{packet_size} B"
            self.all_ips_table.insert("", "end", values=(ip_address, dst_port, size_str))

    def sort_suspicious_table(self):
        items = self.suspicious_table.get_children()
        sorted_items = sorted(items, key=lambda ip: self.ip_bytes_dict.get(ip, 0), reverse=True)
        for index, ip in enumerate(sorted_items):
            self.suspicious_table.move(ip, '', index)

    def on_suspicious_select(self, event):
        if self.suspicious_table.selection():
            self.block_button.config(state="normal")
        else:
            self.block_button.config(state="disabled")

    def on_blocked_select(self, event):
        if self.blocked_table.selection():
            self.unblock_button.config(state="normal")
        else:
            self.unblock_button.config(state="disabled")

    def start_monitoring(self):
        for row in self.all_ips_table.get_children():
            self.all_ips_table.delete(row)
        for row in self.suspicious_table.get_children():
            self.suspicious_table.delete(row)

        self.ip_bytes_dict.clear()
        self.ip_ports_dict.clear()
        self.suspicious_ips.clear()
        self._last_logged_reason.clear()

        self.monitoring_active = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        t = threading.Thread(target=self.monitor_traffic)
        t.daemon = True
        t.start()
        logging.info("Monitoring started")

    def monitor_traffic(self):
        try:
            # на каждый пакет вызывается packet_callback, не храним все пакеты в памяти
            self.sniffer = scapy.AsyncSniffer(prn=self.packet_callback, store=False)
            self.sniffer.start()
            self.sniffer.join()
        except Exception as e:
            logging.error(f"Sniffer error: {e}")
        finally:
            self.sniffer = None

    def stop_monitoring(self):
        self.monitoring_active = False
        try:
            if self.sniffer is not None:
                self.sniffer.stop()
        except Exception as e:
            logging.error(f"Error stopping sniffer: {e}")

        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        logging.info("Monitoring stopped")

    def block_ip(self):
        selected = self.suspicious_table.selection()
        if selected:
            ip = selected[0]

            if ip in self.my_ips:
                print("Refusing to block own IP:", ip)
                logging.warning(f"Refusing to block own IP: {ip}")
                return
            if self.gateway_ip and ip == self.gateway_ip:
                print("Refusing to block default gateway:", ip)
                logging.warning(f"Refusing to block default gateway: {ip}")
                return

            if ip not in self.blocked_ips:
                self.blocked_ips.add(ip)
                self.blocked_table.insert("", "end", values=(ip,))
                self.add_iptables_rule(ip)
                logging.info(f"BLOCK: {ip}")

                if self.suspicious_table.exists(ip):
                    self.suspicious_table.delete(ip)

                self.block_button.config(state="disabled")

    def unblock_ip(self):
        selected = self.blocked_table.selection()
        if selected:
            ip = self.blocked_table.item(selected[0])['values'][0]

            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                self.remove_iptables_rule(ip)
                logging.info(f"UNBLOCK: {ip}")

                self.blocked_table.delete(selected)
                self.unblock_button.config(state="disabled")

                current_bytes = self.ip_bytes_dict.get(ip, 0)
                ports_count = len(self.ip_ports_dict.get(ip, []))

                reasons = []
                if current_bytes > self.SIZE_THR:
                    reasons.append("Traffic Limit")
                if ports_count > self.PORT_SCAN_THR:
                    reasons.append("Port Scanning")

                if reasons:
                    kb_size = round(current_bytes / 1024, 1)
                    kb_str = f"{kb_size} KB"
                    reason_str = ", ".join(reasons)
                    ports_str = str(ports_count)  # +++

                    if not self.suspicious_table.exists(ip):
                        # +++ добавили ports_str
                        self.suspicious_table.insert(
                            "", "end", iid=ip,
                            values=(ip, reason_str, kb_str, ports_str)
                        )
                        self.sort_suspicious_table()

    def add_iptables_rule(self, ip):
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "REJECT"], check=True)
            print(f"BLOCKED: {ip}")
            logging.info(f"iptables REJECT added for {ip}")
        except Exception as e:
            print(f"Error blocking: {e}")
            logging.error(f"iptables block error ip={ip}: {e}")

    def remove_iptables_rule(self, ip):
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "REJECT"], check=True)
            print(f"UNBLOCKED: {ip}")
            logging.info(f"iptables REJECT removed for {ip}")
        except Exception as e:
            print(f"Error unblocking: {e}")
            logging.error(f"iptables unblock error ip={ip}: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = Network(root)
    root.mainloop()
