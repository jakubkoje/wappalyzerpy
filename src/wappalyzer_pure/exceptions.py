class WappalyzerPureError(Exception):
    pass


class PatternError(WappalyzerPureError):
    pass


class DataLoadError(WappalyzerPureError):
    pass


class HeadlessUnavailableError(WappalyzerPureError):
    pass
