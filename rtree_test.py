#!/usr/bin/env python
from my_fastnetmon.rtree import rtree as rtree
from my_fastnetmon.rtree_node import rtree_node as rtree_node

num=1
#print  num.bit_length()
#exit()

tree = rtree()
#tree.add('192.168.0.0/16','192.168.0.0/16')
tree.add('192.168.10.0/24','192.168.10.0/24')
tree.add('192.168.11.0/24','192.168.11.0/24')
tree.add('192.168.12.0/24','192.168.12.0/24')
#tree.add('192.168.8.0/21','192.168.8.0/24')
#tree.add('192.168.12.0/23','192.168.1.0/23')
#tree.add('192.168.12.0/23','192.168.12.0/23')
tree.add('10.0.0.0/23','10.0.0.0/23')
tree.add('10.0.0.0/24','10.0.0.0/24')
tree.add('10.0.1.0/24','10.0.1.0/24')
tree.add('10.0.0.0/16','10.0.0.0/16')
tree.add('0.0.0.0/0','0.0.0.0/0')
print(tree)

print(tree.lookup('10.0.0.1'))
