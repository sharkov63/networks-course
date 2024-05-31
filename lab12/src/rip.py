import threading
import queue
import time
import random

stdout_lock = threading.Lock()

class Network:
    def __init__(self):
        pass

    def read(self):
        self.n = int(input())
        self.ip_addr = [""] * self.n
        for i in range(self.n):
            self.ip_addr[i] = input().strip()
        self.tables = [{} for _ in range(self.n)]
        self.adj = [[] for _ in range(self.n)]
        for i in range(self.n):
            self.adj[i] = list(map(int, input().split()))
            for j in self.adj[i]:
                self.tables[i][j] = (j, 1)
            self.tables[i][i] = (i, 0)
        self.queues = [queue.Queue() for _ in range(self.n)]

    def dump_table(self, i):
        print("Routing table for {}:".format(self.ip_addr[i]))
        print("Dest\t\tNext Hop\tHops")
        for dest, entry in self.tables[i].items():
            print("{}\t{}\t{}".format(self.ip_addr[dest], self.ip_addr[entry[0]], entry[1]))

    def update(self, i, j):
        relaxed = False
        for dest, j_entry in self.tables[j].items():
            i_entry = self.tables[i].get(dest)
            if i_entry == None or i_entry[1] > j_entry[1] + 1:
                self.tables[i][dest] = (j, j_entry[1] + 1)
                relaxed = True
        return relaxed

def routine(network, i):
    while True:
        time.sleep(random.random() * 0.05)
        for j in network.adj[i]:
            network.queues[j].put(i, block=False)
        time.sleep(random.random() * 0.05)
        i_queue = network.queues[i]
        while True:
            try:
                j = i_queue.get(block=True, timeout=0.05)
                if network.update(i, j):
                    with stdout_lock:
                        print("{} relaxed through {}".format(network.ip_addr[i], network.ip_addr[j]))
                        network.dump_table(i)
                        print()
            except queue.Empty:
                pass


def rip_main():
    network = Network()
    network.read()
    threads = [threading.Thread(target=routine, args=(network, i), daemon=True) for i in range(network.n)]
    for i in range(network.n):
        threads[i].start()
    time.sleep(2)
    print()
    print("Final result:")
    for i in range(network.n):
        network.dump_table(i)

if __name__ == '__main__':
    rip_main()
