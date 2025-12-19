
import sys
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

import tkinter as tk
from tkinter import filedialog, messagebox

MIN_PACKETS = 5
PERIOD_THRESHOLD = 0.20 

class BeaconHunter:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.flows = defaultdict(list)
        self.payload_sizes = defaultdict(list)

    def parse_pcap(self):
        print(f"[*] Анализ файла: {self.pcap_path}...")
        try:
            packets = rdpcap(self.pcap_path)
            for p in packets:
                if IP in p:
                    src, dst = p[IP].src, p[IP].dst
                    proto = "TCP" if TCP in p else "UDP" if UDP in p else "OTHER"
                    dport = p[proto].dport if proto != "OTHER" else 0
                    
                    flow_id = (src, dst, dport, proto)
                    self.flows[flow_id].append(float(p.time))
                    self.payload_sizes[flow_id].append(len(p))
            return True
        except Exception as e:
            print(f"[-] Ошибка: {e}")
            return False

    def analyze_flow(self, times, sizes):
        if len(times) < MIN_PACKETS:
            return None

        intervals = np.diff(sorted(times))
        avg = np.mean(intervals)
        std = np.std(intervals)
        jitter = std / avg if avg > 0 else 1

        score = 0
        if jitter < PERIOD_THRESHOLD: score += 60 
        if 5 <= avg <= 300: score += 20          
        if np.std(sizes) < 50: score += 20       

        return {"avg": avg, "jitter": jitter, "score": score, "intervals": intervals}

    def run(self):
        if not self.parse_pcap():
            return

        results = []
        for flow, times in self.flows.items():
            stats = self.analyze_flow(times, self.payload_sizes[flow])
            if stats:
                results.append((stats['score'], flow, stats))

        sorted_results = sorted(results, key=lambda x: x[0], reverse=True)
        top_5 = sorted_results[:5]

        print("\n" + "="*85)
        print(f"{'FLOW':<45} | {'SCORE':<7} | {'JITTER':<8} | {'AVG INT'}")
        print("="*85)
        
        for score, flow, stats in sorted_results[:10]:
            src, dst, port, proto = flow
            print(f"{src} -> {dst}:{port:<5} ({proto:<5}) | {score:<7} | {stats['jitter']:<8.3f} | {stats['avg']:.2f}s")

        if top_5:
            self.visualize_top_n(top_5)
            messagebox.showinfo("Успех", f"Анализ завершен!\nОтчет по {len(top_5)} самым подозрительным потокам сохранен в beacon_report.html")
        else:
            messagebox.showwarning("Результат", "Подозрительной Beacon-активности не обнаружено.")

    def visualize_top_n(self, top_results):
        """Создает один HTML файл с несколькими графиками"""
        n = len(top_results)
        
        fig = make_subplots(
            rows=n, cols=1, 
            subplot_titles=[f"TOP {i+1}: {res[1][0]} -> {res[1][1]} (Score: {res[0]})" for i, res in enumerate(top_results)],
            vertical_spacing=0.05
        )

        for i, (score, flow, stats) in enumerate(top_results):
            row = i + 1
            fig.add_trace(
                go.Scatter(
                    x=list(range(len(stats['intervals']))), 
                    y=stats['intervals'],
                    mode='lines+markers',
                    name=f"Flow {row}"
                ),
                row=row, col=1
            )
            fig.add_hline(y=stats['avg'], line_dash="dash", line_color="red", row=row, col=1)

        fig.update_layout(
            height=400 * n,
            title_text="Beacon Hunter: Top 5 Suspicious Flows Analysis",
            showlegend=False
        )
        
        fig.write_html("beacon_report.html")

def select_file_and_run():
    root = tk.Tk()
    root.withdraw() 

    file_path = filedialog.askopenfilename(
        title="Выберите сетевой дамп (PCAP)",
        filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
    )

    if file_path:
        hunter = BeaconHunter(file_path)
        hunter.run()
    else:
        print("[!] Файл не выбран. Выход.")

if __name__ == "__main__":
    select_file_and_run()
