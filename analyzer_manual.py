
import angr
from angrutils import *

# load your project
p = angr.Project('examples/dd', load_options={'auto_load_libs': False})

# Generate a static CFG
cfg = p.analyses.CFGFast()

# generate a dynamic CFG
main_entry = p.loader.main_object.get_symbol("main").rebased_addr
# cfg = p.analyses.CFGEmulated(fail_fast=False, starts=[main_entry], context_sensitivity_level=1, enable_function_hints=False, keep_state=True, enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,normalize=True)
cfg = p.analyses.CFGEmulated(starts=[main_entry], keep_state=True)

# cdg = p.analyses.CDG(cfg)
# ddg = p.analyses.DDG(cfg)

# print("This is the graph:", cfg.graph)
# print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))

# target_func = cfg.kb.functions.function(name="mmap")
# target_node = cfg.get_any_node(target_func.addr)

# bs = p.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])
# bs = p.analyses.BackwardSlice(cfg, control_flow_slice=True)


# print(bs.dbg_repr())
# print(bs.cfg_nodes_in_slice)

# plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  
# plot_cdg(cfg, cdg, "ais3_cdg")  
# plot_cg(p.kb, "ais3_cg")

import networkx as nx
import queue

graph = cfg.graph
labels = {}
order = nx.topological_sort(graph)
head = order.__next__()

def bfs():

    nodes = queue.Queue()

    nodes.put(head)
    labels[head] = True
    # print(head.name)

    while nodes.qsize() > 0:
        now = nodes.get()
        
        print(now.name)
        for t in graph.neighbors(now):
            if not t in labels:
                nodes.put(t)
                labels[t] = True

def dfs(node, cnt, path, sd):
    # print(node.name)
    # path += path + str(node.name) + " -> "
    ng = 0
    new_path = path + str(node.name)

    if node.name == "mmap":
        cnt += 1

    for edge in graph.out_edges(node, data=True):
        s, d, data = edge
        if not d == node and not data['jumpkind'] == 'Ijk_FakeRet':
            # dfs(d, cnt + 1, new_path + "(" + str(data['jumpkind']) + ")" + " -> ")
            dfs(d, cnt, new_path + " -> ", sd)
            ng += 1

    if ng == 0:
        sd['syscall_cnt'].append(cnt)
        print(new_path + " " + str(cnt))
        
            

shared_data = {'pcnt': 0, 'syscall_cnt': []}
dfs(head, 0, "", shared_data)
print(shared_data)
# print(cfg.graph.edges.data())