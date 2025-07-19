import threading
import time
from scapy.all import sniff, IP
import tkinter as tk
from tkinter import ttk

# GUI App Class
class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer - CodeAlpha Task 1")
        self.root.geometry("800x400")
        self.running = False

        # Table Setup
        self.tree = ttk.Treeview(root, columns=('Time', 'Source', 'Destination', 'Protocol', 'Length'), show='headings')
        self.tree.heading('Time', text='Time')
        self.tree.heading('Source', text='Source IP')
        self.tree.heading('Destination', text='Destination IP')
        self.tree.heading('Protocol', text='Protocol')
        self.tree.heading('Length', text='Length')
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Buttons
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)

        self.start_button = tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=10)

        self.stop_button = tk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=10)

    def start_sniffing(self):
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        thread = threading.Thread(target=self.sniff_packets)
        thread.daemon = True
        thread.start()

    def stop_sniffing(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(filter="ip", prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if not self.running:
            return False

        if IP in packet:
            ip_layer = packet[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            proto_num = ip_layer.proto
            length = len(packet)

            if proto_num == 6:
                proto = 'TCP'
            elif proto_num == 17:
                proto = 'UDP'
            else:
                proto = 'Other'

            timestamp = time.strftime('%H:%M:%S')
            self.tree.insert('', tk.END, values=(timestamp, src, dst, proto, length))


# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
