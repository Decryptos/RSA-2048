"""Load the legacy extensionless engine using supported importlib APIs."""
import importlib.machinery
import importlib.util
from pathlib import Path
import sys


def load_engine(name="decrypto_factor_engine"):
    if name in sys.modules:
        return sys.modules[name]
    loader = importlib.machinery.SourceFileLoader(name, str(Path(__file__).with_name("Main")))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module
