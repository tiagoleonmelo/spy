class Flow:
    """Flow keeping track of source and sanitizers."""
    def __init__(self, source, sanitizers) -> None:
        self.source = source
        self.sanitizers = sanitizers

    def __str__(self) -> str:
        return "%s sans %s(%d)" % (self.source, ';'.join(self.sanitizers), len(self.sanitizers))

    def __repr__(self) -> str:
        return str(self)


class MergedFlow(Flow):
    """Exactly the same as before, but is meant to keep [[]] as a list of sanitizers"""
    def __init__(self, source, sanitizers) -> None:
        super().__init__(source, sanitizers)

    def __str__(self) -> str:
        return "%s sans (%d)" % (self.source, len(self.sanitizers))

    def __repr__(self) -> str:
        return str(self)