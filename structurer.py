from copy import deepcopy

from aggregator import Aggregator
from expressions import JumpExpression
from solidity.splitter import split_bytecode
from structures import *

import sys


class PreLoop(object):
    def __init__(self, header, graph):
        self.graph = deepcopy(graph)

        # loop entry node
        self.header = header

        # nodes with back edge (can be more than one because of continue statement)
        self.tails = []

        # loop exit nodes (can be more than one because of break statement)
        self.exits = []

        # loop nodes
        self.bbs = []

        # loop successors
        self.succ = []

    def __str__(self):
        out = str(hex(self.graph.get_block(self.header).get_entry_address())) + ": "
        out += " blocks: " + str([hex(self.graph.get_block(bb).get_entry_address()) for bb in self.bbs])
        out += " exits: " + str([hex(self.graph.get_block(exit).get_entry_address()) for exit in self.exits])
        out += " tails: " + str([hex(self.graph.get_block(tail).get_entry_address()) for tail in self.tails])
        out += " succ: " + str([hex(self.graph.get_block(s).get_entry_address()) for s in self.succ])
        return out


class Structurer(Aggregator):
    def __init__(self, binary, is_construct=False):
        Aggregator.__init__(self, binary, is_construct)
        for func in self.get_all_functions():
            self.__analyze_function(func)

    def __analyze_function(self, func):

        graph = func.graph
        if self.__has_indirect_jumps(graph):
            return

        sorted_ids = graph.depth_first_search(func.entry_id)
        func_entry = func.entry_id
        for block_id in sorted_ids:
            func_entry = self.__match_unstructured_conditions(block_id, graph, func.entry_id)

        graph.create_dominance_relation(func_entry)
        loops = self.compute_natural_loops(graph, func_entry)

        loop_succs = []
        for l in loops:
            loop_succs.extend(l.succ)

        loop_exits = []
        for l in loops:
            loop_exits.extend(l.exits)

        # currently not in use, only for continue statements needed
        loop_tails = []
        for l in loops:
            loop_tails.extend(l.tails)

        loop_headers = []
        for l in loops:
            loop_headers.append(l.header)

        sorted_ids = graph.depth_first_search(func.entry_id)
        for block_id in sorted_ids:
            self.__match_breaks(block_id, graph, loop_succs, loop_exits, loop_headers)

        sorted_ids = graph.depth_first_search(func_entry)
        for block_id in sorted_ids:
            self.__match_structures(block_id, graph)

        entry_id = func.entry_id
        for block in graph:
            result = block.get_block(entry_id)
            if result is not None:
                func.entry_id = block.get_id()

        func.visualize_function()

    def compute_natural_loops(self, graph, entry_id):
        loops = []

        for block in graph.depth_first_search(entry_id):
            for succ in graph.get_successor_ids(block):
                # Every successor that dominates its predecessor must be the header of a loop.
                # That is, block.succ is a back edge.

                if graph.dominates_over(succ, block):
                    loops.append(self.natural_loop_for_edge(graph, succ, block))

        # logic for determining exit nodes
        for loop in loops:
            for bb in loop.bbs:
                for succ in graph.get_successor_ids(bb):
                    if succ not in loop.bbs:
                        loop.exits.append(bb)
                        loop.succ.append(succ)
            succ_list = loop.succ
            while len(loop.succ) > 1 and succ_list:
                succ_list = []
                for succ in loop.succ:
                    if set(graph.get_predecessor_ids(succ)) <= set(loop.bbs):
                        loop.bbs.append(succ)
                        loop.succ.remove(succ)
                        succ_list.append(s for s in graph.get_successor_ids(succ) if
                                         s not in loop.bbs and graph.dominates_over(loop.header, s))

        # print([str(l) for l in loops])
        return loops

    def natural_loop_for_edge(self, graph, header, tail, loop=None):
        worklist = []
        if not loop:
            loop = PreLoop(header, graph)
            loop.bbs.append(header)

        loop.tails.append(tail)

        if header is not tail:
            loop.bbs.append(tail)
            worklist.append(tail)

        while worklist:
            block = worklist.pop()

            for pred in graph.get_predecessor_ids(block):
                if pred not in loop.bbs:
                    loop.bbs.append(pred)
                    worklist.append(pred)

        return loop

    def __has_indirect_jumps(self, graph):
        indirect_jumps = set()
        for block in graph:
            block_id = block.get_id()
            if block.check_exit_expression("JUMP") \
                    and len(graph.get_successor_ids(block)) > 1:
                indirect_jumps.add(block_id)
        return len(indirect_jumps) != 0

    def __match_unstructured_conditions(self, block_id, graph, func_entry):
        if not graph.has_block(block_id):
            return func_entry
        new_func_entry = func_entry
        original_id, cur_id = block_id, -1
        while cur_id != block_id:
            cur_id = block_id
            block_id = self.__match_combined_if(block_id, graph)

            if new_func_entry == cur_id and cur_id != block_id:
                new_func_entry = block_id

        return new_func_entry

    def __match_breaks(self, block_id, graph, loop_succs, loop_exits, loop_headers):
        if not graph.has_block(block_id):
            return
        original_id, cur_id = block_id, -1
        while cur_id != block_id:
            cur_id = block_id
            block_id = self.__match_break(block_id, graph, loop_succs, loop_exits, loop_headers)

    def __match_structures(self, block_id, graph):
        original_id, cur_id = block_id, -1
        while cur_id != block_id:
            cur_id = block_id
            block_id = self.__match_ifthen(block_id, graph)
            block_id = self.__match_sequence(block_id, graph)
            block_id = self.__match_ifthenelse(block_id, graph)
            block_id = self.__match_loop(block_id, graph)
            block_id = self.__match_do_while_loop(block_id, graph)

    def __match_ifelse(self, a0, graph):
        suc_ids = graph.get_dual_successors(a0)
        if suc_ids is None:
            return a0
        a1 = graph.get_natural_successor(a0)
        a2 = (suc_ids - {a1}).pop()
        post_dom = None
        graph.create_post_dominance_relation()
        for b in graph.depth_first_search(a0):
            if graph.post_dominates_over(b, a0):
                post_dom = b
        if not post_dom:
            return a0
        suc_address = graph[post_dom].get_entry_address()
        new_id = graph.allocate_id()

        newa1 = self.__match_sequence(a1, graph)
        newa2 = self.__match_sequence(a2, graph)

        block = IfThenElse(new_id, suc_address, graph[a0], graph[newa1], graph[newa2])
        graph.add_block(block)
        graph.transfer_predecessors(a0, new_id)
        graph.add_edge(new_id, post_dom)
        graph.remove_blocks({a0, newa1, newa2})
        return new_id

    def __match_sequence(self, a0, graph):
        sequence = [a0]
        prev_id = a0
        while True:
            cur_id = graph.get_single_successor(prev_id)
            if cur_id is None:
                break
            if graph.get_single_predecessor(cur_id) != prev_id:
                break
            sequence.append(cur_id)
            prev_id = cur_id
        if len(sequence) == 1:
            return a0
        an = sequence[-1]
        new_id = graph.allocate_id()
        blocks = [graph[i] for i in sequence]
        block = Seq(new_id, graph[an].get_exit_address(), blocks)
        graph.add_block(block)

        graph.transfer_predecessors(a0, new_id)
        graph.transfer_successors(an, new_id)

        graph.remove_blocks(sequence)
        return new_id

    def __match_combined_if(self, a0, graph):
        # block a0 has exactly two successors
        suc_ids = graph.get_dual_successors(a0)
        if suc_ids is None:
            return a0

        # the successor a2 of block a0 must be also the successor of block a1 and a2 must have exactly 2 successors
        a1 = graph.get_natural_successor(a0)
        a2 = graph.get_single_successor(a1)
        if a2 not in suc_ids or not graph.get_dual_successors(a2):
            return a0

        # the block a2 must have a JUMPI expression
        block = graph.get_block(a2)
        if isinstance(block, ExpressionBlock) and not (
                block.get_items() and isinstance(block.get_items()[0], JumpIExpression)):
            return a0

        # the block a2 must have at most 6 bytes
        if block.get_exit_address() > block.get_entry_address() + 6:  # heuristic approximation
            return a0

        # the block a2
        if isinstance(block, IfCombined) and not block.is_first_block_jumpi():
            return a0

        # the IfCombined structure is created from the 3 blocks and the preds und succs are adapted
        new_id = graph.allocate_id()
        block = IfCombined(new_id, -1, graph[a0], graph[a1], graph[a2])
        graph.add_block(block)
        graph.transfer_predecessors(a0, new_id)
        graph.transfer_successors(a2, new_id)
        graph.remove_blocks({a0, a1, a2})
        return new_id

    def __match_break(self, a0, graph, loop_succs, loop_exits, loop_headers):
        suc = None
        for s in graph.get_successor_ids(a0):
            if s in loop_succs:
                suc = s
                break

        if not suc:
            return a0

        graph[a0].remove_end_jump()

        if a0 in loop_exits or a0 in loop_headers:
            new_id = graph.allocate_id()
            block = ExpressionBlock(new_id, -1)  # dummy address #1
            block.add_break()
            graph.add_block(block)

            tail_id = graph.allocate_id()
            tail = ExpressionBlock(tail_id, -2)  # dummy address #2
            graph.add_block(tail)

            graph.transfer_successors(a0, tail_id)
            graph.add_edge(a0, new_id)
            graph.add_edge(a0, tail_id)
            graph.add_edge(new_id, tail_id)
            return a0

        preds = []
        nodes = [a0]
        while nodes:
            n = nodes.pop()
            single_pred = graph.get_single_predecessor(n)
            if single_pred and single_pred not in preds:
                suc_ids = graph.get_dual_successors(single_pred)
                a1 = graph.get_natural_successor(single_pred)
                if suc_ids and a1 == n:
                    a2 = (suc_ids - {a1}).pop()
                    graph[a0].add_break()
                    graph.remove_edge(a0, suc)
                    graph.add_edge(a0, a2)
                    return a0
            preds = graph.get_predecessor_ids(n)
            nodes.extend(graph.get_predecessor_ids(n))

        return a0

    def __match_ifthen(self, a0, graph):
        suc_ids = graph.get_dual_successors(a0)
        if suc_ids is None:
            return a0
        a1 = graph.get_natural_successor(a0)
        a2 = graph.get_single_successor(a1)
        if a2 not in suc_ids:
            return a0

        new_id = graph.allocate_id()
        block = IfThen(new_id, graph[a2].get_entry_address(), graph[a0], graph[a1])
        graph.add_block(block)
        graph.transfer_predecessors(a0, new_id)
        graph.remove_blocks({a0, a1})
        graph.add_edge(new_id, a2)
        return new_id

    def __match_ifthenelse(self, a0, graph):
        suc_ids = graph.get_dual_successors(a0)
        if suc_ids is None:
            return a0
        a1 = graph.get_natural_successor(a0)
        a2 = (suc_ids - {a1}).pop()
        if graph.get_single_predecessor(a1) != graph.get_single_predecessor(a2):
            return a0
        a3 = graph.get_single_successor(a1)
        if a3 is None or a3 != graph.get_single_successor(a2):
            return a0
        suc_address = graph[a3].get_entry_address()
        new_id = graph.allocate_id()
        block = IfThenElse(new_id, suc_address, graph[a0], graph[a1], graph[a2])
        graph.add_block(block)
        graph.transfer_predecessors(a0, new_id)
        graph.add_edge(new_id, a3)
        graph.remove_blocks({a0, a1, a2})
        return new_id

    def __match_loop(self, a0, graph):
        suc_ids = graph.get_dual_successors(a0)
        if suc_ids is None:
            return a0
        a1, a2 = suc_ids
        if graph.get_single_successor(a2) == a0:
            a1, a2 = a2, a1
        if graph.get_single_successor(a1) != a0 \
                or graph.get_single_predecessor(a1) != a0:
            return a0

        # a1 is guaranteed to be the loop tail since above conditions met
        # it is not a while-loop if there is only a jump expression in the loop tail
        block = graph.get_block(a1)
        if isinstance(block, ExpressionBlock) and block.get_items() and isinstance(block.get_items()[0],
                                                                                   JumpExpression):
            return a0

        new_id = graph.allocate_id()
        suc_address = graph[a2].get_entry_address()
        block = Loop(new_id, suc_address, graph[a0], graph[a1])
        graph.add_block(block)
        graph.transfer_predecessors(a0, new_id)
        graph.add_edge(new_id, a2)
        graph.remove_blocks({a0, a1})
        return new_id

    def __match_do_while_loop(self, a0, graph):
        suc_ids = graph.get_dual_successors_loop(a0)
        if suc_ids is None:
            return a0
        a1, a2 = suc_ids
        if graph.get_single_successor(a2) == a0:
            a1, a2 = a2, a1

        if graph.get_single_predecessor(a2) != a0:
            return a0

        # loop block must be its own successor or the successor of the successor
        if a1 != a0 and graph.get_single_successor(a1) != a0:
            return a0

        block = graph.get_block(a1)
        # it is also a do-while-loop if there is only a jump expression in the loop tail
        if isinstance(block, ExpressionBlock) and block.get_items() \
                and isinstance(block.get_items()[0], JumpExpression):
            graph.add_edge(a0, a0)
            graph.remove_blocks({a1})
            a1 = a0

        new_id = graph.allocate_id()
        suc_address = graph[a1].get_entry_address()
        block = DoWhileLoop(new_id, suc_address, graph[a0])
        graph.add_block(block)
        graph.transfer_predecessors(a0, new_id)
        graph.add_edge(new_id, a2)
        graph.remove_blocks({a0, a1})
        return new_id

    def visualize_functions(self):
        for func in self.get_all_functions():
            func.visualize_function()


if __name__ == "__main__":
    input_file = open(sys.argv[1])
    line = input_file.readline().strip()
    if " " in line:
        line = line.split(" ")[1]
    input_file.close()

    programs = split_bytecode(line)

    for p in programs:
        a = Structurer(p.bytecode.hex(), p.is_construct)
        if "-v" in sys.argv:
            a.visualize_functions()
