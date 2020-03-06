__all__ = ['rtree']

from rtree_node import rtree_node,ip2int

class rtree:
    def __init__(self):
        self.root = rtree_node('0.0.0.0/0')

    def __repr__(self):
        return repr(self.root)

    def add(self,prefix,value=None):
        self.root.add_branch(rtree_node(prefix,value))
        return

    def lookup(self,host):
        node = self.root.find_down(ip2int(host),self.root)
        return node.value

