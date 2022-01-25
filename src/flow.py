from itertools import chain


class Flow:
    """I need an easy way to produce output. Im done with managing dictionaries of lists."""
    def __init__(self) -> None:
        self.source = ''
        self.chain = []
        self.sanitizers = []
        self.sink = ''
        self.children = []

    def __str__(self):
        m='source='+str(self.source)+'##sink='+str(self.sink)+'##'+str(self.chain)+'##'+str(self.sanitizers)
        c=[str(i) for i in self.children]
        s=''.join(c)
        if len(c)==0:
            s='NO CHILDS'
        return 'FLOW:'+m+'\nCHILDS:    '+s+'\nENDFLOW####\n'

    def merge(self, newf):
        #print(self.chain)
        
        for child in self.children:
            flow=Flow()
            if child.source:
                flow.source=child.source
            if self.sink:
                flow.sink=self.sink
            flow.chain.extend(self.chain)
            flow.chain.extend(child.chain)
            if len(child.children)>0:
                child.chain=flow.chain
            if len(child.children)==0:
                newf.append(flow)
            #newf.append(flow)
            child.merge(newf)
