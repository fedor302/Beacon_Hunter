
import sys
import numpy as np
import pandas as pd
import plotly.express as px
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
        
        print("\n" + "="*85)
        print(f"{'FLOW':<45} | {'SCORE':<7} | {'JITTER':<8} | {'AVG INT'}")
        print("="*85)
        
        for score, flow, stats in sorted_results[:10]:
            src, dst, port, proto = flow
            print(f"{src} -> {dst}:{port:<5} ({proto:<5}) | {score:<7} | {stats['jitter']:<8.3f} | {stats['avg']:.2f}s")

        if sorted_results and sorted_results[0][0] >= 50:
            self.visualize(sorted_results[0])
            messagebox.showinfo("Успех", f"Анализ завершен!\nСамый подозрительный поток: {sorted_results[0][1][1]}\nГрафик сохранен в beacon_report.html")
        else:
            messagebox.showwarning("Результат", "Подозрительной Beacon-активности не обнаружено.")

    def visualize(self, top_match):
        score, flow, stats = top_match
        df = pd.DataFrame({'Request': range(len(stats['intervals'])), 'Interval': stats['intervals']})
        fig = px.line(df, x='Request', y='Interval', title=f"Beacon Detection: {flow[0]} -> {flow[1]} (Score: {score})", markers=True)
        fig.add_hline(y=stats['avg'], line_dash="dash")
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
