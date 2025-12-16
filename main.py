import sys
import numpy as np
import pandas as pd
import plotly.express as px
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

MIN_PACKETS = 5 
PERIOD_THRESHOLD = 0.2

class BeaconHunter:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.flows = defaultdict(list)
        self.payload_sizes = defaultdict(list)

    def parse_pcap(self):
        print(f"[*] Чтение и анализ PCAP файла: {self.pcap_path}...")
        try:
            packets = rdpcap(self.pcap_path)
        except Exception as e:
            print(f"[-] Ошибка при чтении: {e}")
            sys.exit(1)

        for p in packets:
            if IP in p:
                src, dst = p[IP].src, p[IP].dst
                proto = "TCP" if TCP in p else "UDP" if UDP in p else "OTHER"
                dport = p[proto].dport if proto != "OTHER" else 0
                
                flow_id = (src, dst, dport, proto)
                self.flows[flow_id].append(float(p.time))
                self.payload_sizes[flow_id].append(len(p))

    def analyze_flow(self, times, sizes):
        """Статистический анализ одного потока"""
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

        return {
            "avg": avg,
            "jitter": jitter,
            "score": score,
            "intervals": intervals,
            "count": len(times)
        }

    def run(self):
        self.parse_pcap()
        results = []

        for flow, times in self.flows.items():
            stats = self.analyze_flow(times, self.payload_sizes[flow])
            if stats:
                results.append((stats['score'], flow, stats))

        sorted_results = sorted(results, key=lambda x: x[0], reverse=True)
        self.print_results(sorted_results)
        
        if sorted_results and sorted_results[0][0] >= 50:
            self.visualize(sorted_results[0])

    def print_results(self, results):
        print("\n" + "="*85)
        print(f"{'FLOW (Source -> Destination:Port)':<45} | {'SCORE':<7} | {'JITTER':<8} | {'AVG INT'}")
        print("="*85)
        
        for score, flow, stats in results[:10]:
            src, dst, port, proto = flow
            flow_str = f"{src} -> {dst}:{port} ({proto})"
            print(f"{flow_str:<45} | {score:<7} | {stats['jitter']:<8.3f} | {stats['avg']:.2f}s")

    def visualize(self, top_match):
        score, flow, stats = top_match
        df = pd.DataFrame({
            'Request': range(len(stats['intervals'])),
            'Interval (sec)': stats['intervals']
        })
        
        title = f"Beacon Pattern Detection: {flow[0]} -> {flow[1]} (Score: {score})"
        fig = px.line(df, x='Request', y='Interval (sec)', title=title, markers=True)
        fig.add_hline(y=stats['avg'], line_dash="dash", annotation_text="Average Interval")
        
        fig.write_html("beacon_report.html")
        print(f"\n[!] Интерактивный отчет создан: beacon_report.html")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python main.py <file.pcap>")
        sys.exit(1)

    hunter = BeaconHunter(sys.argv[1])
    hunter.run()
