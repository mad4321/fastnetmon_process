__all__ = []

class rtree_node:
    def __init__(self, prefix=None,value=None):
        (net,bit) = prefix.split('/')
        self.prefix = net
        self.bit = int(bit)
        self.value = value
        self.branch_0 = None
        self.branch_1 = None

    def get_value(self):
        return self.value

    def get(self):
        return (self.prefix,self.bit)

    def get_branch(self,bit):
        if (bit <> 0):
            return self.branch_1
        else:
            return self.branch_0

