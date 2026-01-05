
###
### Мониторинг сетевого трафика в GUI.
### Позволяет видеть IP-адреса, помечать подозрительные и блокировать их.
###
### (1) scapy.sniff
###
### Получение копий сетевых пакетов, проходящих через интерфейс,
### до того как они будут обработаны приложениями или стеком TCP/IP.
###
### (2) ip_bytes_dict
###
### Словарь: количество байт, полученных от каждого IP-адреса.
### `IP -> ip_bytes_dict_num`
### По мере поступления пакетов к значению прибавляется len(packet).
### Если накопилось больше заданного порога (500 байт),
### IP помечается как подозрительный.
###
### (3) iptables
###
### Системная утилита Linux для настройки сетевого фильтра ядра.
### `iptables -A INPUT -s 1.2.3.4 -j DROP`

import scapy.all as scapy
#
# scapy.sniff
#  перехватывает пакеты из сетевого интерфейса
#
# scapy.IP
#  объект для доступа к IP-заголовку
#

import tkinter as tk
#
# tk.Tk, tk.Frame, tk.Label, tk.Button
#  окно и виджеты GUI
#

from tkinter import ttk
#
# ttk.Treeview
# таблица с колонками
#

import threading
#
# threading.Thread
#  запуск мониторинга в отдельном потоке,
#  чтобы не блокировать GUI
#

import subprocess
#
# subprocess.run
# системные команды (вызов iptables)
#


class Network:

    root:           tk.Tk          # GUI
    ip_bytes_dict:  dict  = {}     # IP -> общий объём пакетов
    suspicious_ips: set   = set()  # подозрительные  IP
    blocked_ips:    set   = set()  # заблокированные IP
    is_active:      bool  = False  # флаг активности мониторинга
    SIZE_THR:       int   = 500    # size threshold (byte)

    # Инициализация GUI
    def __init__(self, root):

        self.root = root
        self.root.title("IP -> байт получено")
        # self.root.geometry("1200x360")
        self.root.attributes('-fullscreen', True)

        # создать фреймы для трёх таблиц
        all_ips_frame = tk.Frame(root)
        all_ips_frame.grid(row=0, column=0, padx=10, pady=10, sticky="n")

        suspicious_ips_frame = tk.Frame(root)
        suspicious_ips_frame.grid(row=0, column=1, padx=10, pady=10, sticky="n")

        blocked_ips_frame = tk.Frame(root)
        blocked_ips_frame.grid(row=0, column=2, padx=10, pady=10, sticky="n")

        # таблица для всех IP
        tk.Label(all_ips_frame, text="Строка - один принятый пакет").pack(side="top")
        self.all_ips_table = ttk.Treeview(all_ips_frame, columns=("IP", "Port", "Size"), show="headings", height=10)
        self.all_ips_table.heading("IP", text="IP")
        self.all_ips_table.heading("Port", text="Port")
        self.all_ips_table.heading("Size", text="Size")
        self.all_ips_table.pack(side="top", fill="both", expand=True)

        # кнопки управления мониторингом
        self.start_button = tk.Button(all_ips_frame, text="Start", command=self.start_monitoring)
        self.start_button.pack(fill="x", padx=0, pady=5)
        self.stop_button = tk.Button(all_ips_frame, text="Stop", command=self.stop_monitoring)
        self.stop_button.pack(fill="x", padx=0, pady=0)

        # таблица подозрительных IP
        tk.Label(suspicious_ips_frame, text="Подозрительные IP").pack(side="top")
        self.suspicious_ips_table = ttk.Treeview(suspicious_ips_frame, columns=("IP", "Reason"), show="headings", height=10)
        self.suspicious_ips_table.heading("IP", text="IP")
        self.suspicious_ips_table.heading("Reason", text="Reason")
        self.suspicious_ips_table.pack(side="top", fill="both", expand=True)

        # кнопка блокировки выбранного IP
        self.block_button = tk.Button(suspicious_ips_frame, text="Block", command=self.block_ip)
        self.block_button.pack(fill="x", padx=0, pady=5)

        # таблица заблокированных IP
        tk.Label(blocked_ips_frame, text="Заблокированные IP").pack(side="top")
        self.blocked_ips_table = ttk.Treeview(blocked_ips_frame, columns=("IP",), show="headings", height=10)
        self.blocked_ips_table.heading("IP", text="IP")
        self.blocked_ips_table.pack(side="top", fill="both", expand=True)

        # кнопка разблокировки выбранного IP
        self.unblock_button = tk.Button(blocked_ips_frame, text="Unblock", command=self.unblock_ip)
        self.unblock_button.pack(fill="x", padx=0, pady=5)

    # Обработчик одного полученного пакета
    def packet_callback(self, packet: scapy.Packet):

        if packet.haslayer(scapy.IP):
            ip_address  = packet[scapy.IP].src
            packet_size = len(packet)

            # Учёт количества байт по IP
            if ip_address not in self.ip_bytes_dict:
                self.ip_bytes_dict[ip_address] = 0
            self.ip_bytes_dict[ip_address] += packet_size

            # выявить подозрительный IP, если превышен порог
            if self.ip_bytes_dict[ip_address] > self.SIZE_THR:
                if ip_address not in self.suspicious_ips:
                    self.suspicious_ips.add(ip_address)
                    self.suspicious_ips_table.insert("", "end",
                        values=(ip_address, "Size limit exceeded"))

            # добавить в таблицу всех IP, если не заблокирован
            if ip_address not in self.blocked_ips:
                if packet.haslayer(scapy.TCP):
                    port = packet[scapy.TCP].sport
                elif packet.haslayer(scapy.UDP):
                    port = packet[scapy.UDP].sport
                else:
                    port = "-"
                val = (ip_address, port, packet_size)
                self.all_ips_table.insert("", "end", values=val)

    # Запустить мониторинг: очистить таблицы и активировать sniff
    def start_monitoring(self):
        # очистить таблицы
        self.suspicious_ips_table.delete(*self.suspicious_ips_table.get_children())
        self.all_ips_table.delete(*self.all_ips_table.get_children())

        self.monitoring_active = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        # запустить отдельный поток для scapy.sniff
        monitoring_thread = threading.Thread(target=self.monitor_traffic)
        monitoring_thread.daemon = True
        monitoring_thread.start()
        print("Monitoring started")

    # Фоновая функция для захвата пакетов
    def monitor_traffic(self):
        # перехватывать пакеты и вызывать callback
        scapy.sniff(prn=self.packet_callback, store=0)

    # Остановить мониторинг
    def stop_monitoring(self):
        self.monitoring_active = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        print("Monitoring stopped")

    # Заблокировать выбранный подозрительный IP
    def block_ip(self):
        selected_item = self.suspicious_ips_table.selection()
        if selected_item:
            ip_address = self.suspicious_ips_table.item(
                selected_item[0])['values'][0]
            if ip_address not in self.blocked_ips:
                self.blocked_ips.add(ip_address)
                self.blocked_ips_table.insert("", "end", values=(ip_address,))
                # применить iptables для блокировки
                self.add_iptables_rule(ip_address)
                # удалить из таблицы подозрительных
                self.suspicious_ips_table.delete(selected_item)

    # Разблокировать выбранный IP
    def unblock_ip(self):
        selected_item = self.blocked_ips_table.selection()
        if selected_item:
            ip_address = self.blocked_ips_table.item(
                selected_item[0])['values'][0]
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                # снять правило iptables
                self.remove_iptables_rule(ip_address)
                # удалить из таблицы заблокированных
                self.blocked_ips_table.delete(selected_item)

    # Добавить правило iptables для блокировки IP
    def add_iptables_rule(self, ip_address: str):
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT",
                            "-s", ip_address, "-j", "DROP"], check=True)
            print(f"IP address blocked with iptables: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP address {ip_address}: {e}")

    # Удалить правило iptables для IP
    def remove_iptables_rule(self, ip_address: str):
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT",
                            "-s", ip_address, "-j", "DROP"], check=True)
            print(f"IP address unblocked with iptables: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP address {ip_address}: {e}")


# Запуск: обработка пакетов + GUI
if __name__ == "__main__":
    root = tk.Tk()
    monitor = Network(root)
    root.mainloop()
