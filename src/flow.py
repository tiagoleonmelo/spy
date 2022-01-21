class Flow:
    """I need an easy way to produce output. Im done with managing dictionaries of lists."""
    def __init__(self, source, tainters, sanitizers) -> None:
        self.source = source
        self.tainters = tainters
        self.sanitizers = sanitizers