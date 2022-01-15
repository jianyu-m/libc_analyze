
import angr
from angrutils import *
import networkx as nx
import queue
import sys

# load your project
p = angr.Project('/home/jianyu/muslc-build/lib/libc.so', load_options={'auto_load_libs': False})

# Generate a static CFG
cfg = p.analyses.CFGFast()

func_name = "main"
func_check = "do_two"

cntt = 0

def process_func(func_name, func_check):
    global cntt
    
    # if cntt < 296:
    #     cntt += 1
    #     return
    
    # generate a dynamic CFG
    main_entry = p.loader.main_object.get_symbol(func_name).rebased_addr
    try:
        cfg = p.analyses.CFGEmulated(starts=[main_entry], keep_state=False)
    except:
        print("error")
    # plot_cfg(cfg, "cfg/" + func_name + "_cfg", format="pdf", asminst=True, remove_imports=True, remove_path_terminator=True)  

    # bfs
    graph = cfg.graph
    labels = {}
    order = graph.nodes()
    head = list(order)[0]
    out_cnts = {}

    def bfs():
        nodes = queue.Queue()
        nodes.put((head, 0))
        labels[(head, 0)] = True

        while nodes.qsize() > 0:
            now, cnt = nodes.get()
            ng = 0
            # print(now.name)
            if now.name == func_check:
                if cnt < 2:
                    cnt += 1
            for edge in graph.out_edges(now, data=True):
                s, d, data = edge
                if not d == now and not data['jumpkind'] == 'Ijk_FakeRet':
                    if not (d, cnt) in labels:
                        nodes.put((d, cnt))
                        labels[(d, cnt)] = True
                    ng += 1
            if ng == 0:
                out_cnts[now] = 1
    shared_data = {'pcnt': 0, 'syscall_cnt': [], 'labels': {}, 'paths': {}}
    shared_data['labels'][head] = 1
    bfs()
    # print(out_cnts)

    pset = {}
    for n, c in labels:
        if n in out_cnts:
            pset[c] = 1
            # print(n.name, c)
    print(cntt, func_name, list(pset.keys()))
    cntt += 1

def dfs(node, cnt, path, sd):
    # print(node.name)
    # path += path + str(node.name) + " -> "
    ng = 0
    new_path = path + str(node.name)

    if node.name == "syscall":
        cnt += 1

    # print(node.name)
    for edge in graph.out_edges(node, data=True):
        s, d, data = edge
        if not d == node and not data['jumpkind'] == 'Ijk_FakeRet':
            if not d in sd['labels'] or sd['labels'][d] < 1:
                # dfs(d, cnt + 1, new_path + "(" + str(data['jumpkind']) + ")" + " -> ")
                # print(node.name + str(data))
                if not d in sd['labels']:
                    sd['labels'][d] = 1
                else:
                    sd['labels'][d] += 1
                dfs(d, cnt, new_path + " -> ", sd)
                sd['labels'][d] -= 1
            ng += 1
        

    if ng == 0:
        sd['syscall_cnt'].append(cnt)
        pp = new_path + " " + str(cnt)
        if not pp in sd['paths']:
            sd['paths'][pp] = 1
            print(pp)
        else:
            print("duplicated")

funcs = []
with open("libc.txt", "r") as f:
    for line in f.readlines():
        # print(line[:-1], ":")
        funcs.append(line[:-1])

# print(funcs)
for func in funcs:
    process_func(func, "do_syscall")
# print("Argument List:", str(sys.argv[1]))
# process_func(sys.argv[1], "do_syscall")