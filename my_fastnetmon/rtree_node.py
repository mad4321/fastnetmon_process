__all__ = []

import socket
import struct

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def get_bit(addr,bit):
    return 1 if (addr & (1 << (31-bit))) else 0

class rtree_node:
    def __init__(self, prefix='0.0.0.0/0',value=None):
        (net,bit) = prefix.split('/')
        self.prefix = net
        self.bit    = int(bit)
        self.num_prefix = ip2int(net)
        self.bit_mask   = ~((1 << (32-self.bit)) - 1)
        self.value  = value
        self.branch = [None,None]

    def __repr__(self):
        out = ''
#        out = self.prefix+'/'+str(self.bit)
        if (self.value):
            out = out + str(self.value) + "\n"
        if (self.branch[0]):
            out = out + repr(self.branch[0])
        if (self.branch[1]):
            out = out + repr(self.branch[1])
        return out

    def get_value(self):
        return self.value

    def set_value(self,value):
        self.value = value

    def get_bit(self):
        return self.bit

    def get(self):
        return (self.prefix,self.bit)

    def check_bit(self,bit):
        return get_bit(self.num_prefix,bit)

    def get_branch(self,bit):
        if (bit <> 0 and bit <> 1):
            return None
        return self.branch[bit]


    def add_branch(self,node):
        bit = node.check_bit(self.bit)

        #print("add prefix %s to %s"%(node.prefix+'/'+str(node.bit),self.prefix+'/'+str(self.bit)))
        if (self.num_prefix == node.num_prefix and self.bit_mask == node.bit_mask):
            #print "prefix exists"
            self.value = node.value
            return

        if (not self.branch[bit]):
            #print "set new prefix"
            self.branch[bit] = node
            return

        #print("%d %d %d"%(self.branch[bit].num_prefix,node.num_prefix,self.branch[bit].bit_mask))
        #if exist and new node below, then add new node to exist node
        if (self.branch[bit].get_bit()<=node.get_bit() and (node.num_prefix & self.branch[bit].bit_mask == self.branch[bit].num_prefix)):
            #print(" append to %s"%(self.branch[bit].prefix+'/'+str(self.branch[bit].bit)))
            self.branch[bit].add_branch(node)
            return

        #if exist and new node before or same
#        if (self.branch[bit].get_bit() >= node.get_bit() or True):
        new_mask = node.num_prefix ^ self.branch[bit].num_prefix
        new_bit  = 32-new_mask.bit_length()
        new_pref = int2ip(node.num_prefix & ~new_mask)+'/'+str(new_bit)
        if (new_bit<node.get_bit()):
            #print("insert empty branch %s"%(new_pref))
            new_node = rtree_node(new_pref,None)
            new_node.add_branch(node)
            new_node.add_branch(self.branch[bit])
            self.branch[bit]=new_node
        else:
            node.add_branch(self.branch[bit])
            self.branch[bit]=node
        return

    def find_down(self,host,prev_host=None):
        bit = get_bit(host,self.bit)
        if (self.value):
            prev_host = self
        if (self.branch[bit] and (host & self.branch[bit].bit_mask == self.branch[bit].num_prefix)):
            return self.branch[bit].find_down(host,prev_host)
        else:
            return self if self.value else prev_host


