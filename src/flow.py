from itertools import chain


class Flow:
    """I need an easy way to produce output. Im done with managing dictionaries of lists."""
    def __init__(self, source) -> None:
        self.source = ''
        self.chain = []
        self.sanitizers = []
        self.sink = ''

    def set_source(self, source):
        self.source=source

    def set_sink(self, sink):
        self.sink=sink
    
    def add_to_chain(self, chain):
        self.chain.extend(chain)

    def add_to_san(self, sans):
        self.sanitizers.extend(sans)