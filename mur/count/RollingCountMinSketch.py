from amaranth import *
from transactron import *

from mur.count.CountMinSketch import CountMinSketch

__all__ = ["RollingCountMinSketch"]


class RollingCountMinSketch(Elaboratable):
    """
    RollingCountMinSketch merges three CountMinSketch instances to provide a rolling
    count-min sketch. It allows for live updates and queries while maintaining
    the ability to clear the data structure. Every CountMinSketch instance has one of three roles:
    1. **Insert**: This instance is used to insert new data.
    2. **Query**: This instance is used to query the count of data.
    3. **Clear**: This instance is being cleared so can be used for the next insert.

    Atributes
    ----------
        depth (int): Number of hash tables (rows) in the sketch.
        width (int): The size of CountHashTab (number of hash buckets).
        counter_width (int): Number of bits in each counter.
        input_data_width (int): Number of bits in each input data.
        hash_params (list[tuple[int, int]] | None): List of tuples containing
            hash coefficients (a, b) for each row. If None, default values are used.

    Methods
    -------
        set_mode(mode: int): Set the mode of the sketch (0 for insert, 1 for query).
        change_roles(): Change the roles of the CountMinSketch instances so the insert
            instance becomes the query instance, the query instance becomes the clear
            instance, and the clear instance becomes the insert instance.
        input(data: int): Insert data into the sketch or request a query for the count of data depending
            on the current mode.
        output(): Get the count and valid flag from the last query.
    """

    def __init__(
        self,
        *,
        depth: int,
        width: int,
        counter_width: int,
        input_data_width: int,
        hash_params: list[tuple[int, int]] | None = None,
    ) -> None:
        self.depth = depth
        self.width = width
        self.counter_width = counter_width
        self.item_width = input_data_width

        self.set_mode = Method(i=[("mode", 1)])
        self.change_roles = Method()
        self.input = Method(i=[("data", self.item_width)], o=[("mode", 1)])
        self.output = Method(o=[("count", self.counter_width), ("valid", 1)])

        self._cms0 = CountMinSketch(
            depth=depth,
            width=width,
            counter_width=counter_width,
            input_data_width=self.item_width,
            hash_params=hash_params,
        )
        self._cms1 = CountMinSketch(
            depth=depth,
            width=width,
            counter_width=counter_width,
            input_data_width=self.item_width,
            hash_params=hash_params,
        )
        self._cms2 = CountMinSketch(
            depth=depth,
            width=width,
            counter_width=counter_width,
            input_data_width=self.item_width,
            hash_params=hash_params,
        )

        self._head = Signal(range(3), init=0)
        self._mode = Signal(1, init=0)

    def elaborate(self, platform):
        m = TModule()
        m.submodules += [self._cms0, self._cms1, self._cms2]

        @def_method(m, self.input)
        def _(data):
            with m.If(self._mode == 0):
                with m.Switch(self._head):
                    with m.Case(0):
                        self._cms0.insert(m, data=data)
                    with m.Case(1):
                        self._cms1.insert(m, data=data)
                    with m.Case(2):
                        self._cms2.insert(m, data=data)
            with m.Else():

                with m.Switch(self._head):
                    with m.Case(0):
                        self._cms1.query_req(m, data=data)
                    with m.Case(1):
                        self._cms2.query_req(m, data=data)
                    with m.Case(2):
                        self._cms0.query_req(m, data=data)
            return {"mode": self._mode}

        @def_method(m, self.output)
        def _():
            r0 = self._cms0.query_resp(m)
            r1 = self._cms1.query_resp(m)
            r2 = self._cms2.query_resp(m)

            valid = Signal(1)
            count = Signal(self.counter_width)

            m.d.comb += [
                valid.eq(r0["valid"] | r1["valid"] | r2["valid"]),
                count.eq(
                    Mux(
                        r0["valid"],
                        r0["count"],
                        Mux(r1["valid"], r1["count"], r2["count"]),
                    )
                ),
            ]
            return {"count": count, "valid": valid}

        @def_method(m, self.change_roles)
        def _():
            cur_query = (self._head + 1) % 3

            m.d.sync += self._head.eq((self._head + 2) % 3)

            with m.Switch(cur_query):
                with m.Case(0):
                    self._cms0.clear(m)
                with m.Case(1):
                    self._cms1.clear(m)
                with m.Case(2):
                    self._cms2.clear(m)

        @def_method(m, self.set_mode)
        def _(mode):
            m.d.sync += self._mode.eq(mode)

        return m
