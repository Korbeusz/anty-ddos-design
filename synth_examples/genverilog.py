from amaranth.lib.wiring import Component

from transactron import TransactionComponent
from transactron.utils import DependencyManager, DependencyContext
from transactron.utils.gen import generate_verilog


def gen_verilog(component: Component, output_path: str):
    with DependencyContext(DependencyManager()):
        top = TransactionComponent(
            component, dependency_manager=DependencyContext.get()
        )

        verilog_text, gen_info = generate_verilog(top)

        gen_info.encode(f"{output_path}.json")
        with open(output_path, "w") as f:
            f.write(verilog_text)
