
import angr
from angrutils import *

# load your project
p = angr.Project('/home/jianyu/muslc-build/lib/libc.so', load_options={'auto_load_libs': False})

# Generate a static CFG
cfg = p.analyses.CFGFast()

# generate a dynamic CFG
main_entry = p.loader.main_object.get_symbol("remove").rebased_addr
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

plot_cfg(cfg, "muslc_cfg", format="pdf", asminst=True, remove_imports=True, remove_path_terminator=True)  
# plot_cdg(cfg, cdg, "ais3_cdg")  
plot_cg(p.kb, "muslc_cg", format="pdf")