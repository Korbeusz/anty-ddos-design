from amaranth import *
from transactron import *

from mur.count.CountHashTab import CountHashTab

__all__ = ["CountMinSketch"]


class CountMinSketch(Elaboratable):
    """
    CountMinSketch is a probabilistic data structure that serves as a frequency
    counter for data streams. It uses multiple hash tables to estimate the
    frequency of elements in a stream, allowing for fast insertions and
    queries. All methods are always ready for future compatibility with RollingCountMinSketch.

    Attributes
    ----------
        depth (int): Number of hash tables (rows) in the sketch.
        width (int): The size of CountHashTab (number of hash buckets).
        counter_width (int): Number of bits in each counter.
        input_data_width (int): Number of bits in each input data.
        hash_params (list[tuple[int, int]] | None): List of tuples containing
            hash coefficients (a, b) for each row. If None, default values are used.

    Methods
    -------
        insert(data: int): Insert data into the sketch.
        query_req(data: int): Request a query for the count of data.
        query_resp(): Get the count and valid flag from the last query.
        clear(): Clear the sketch. Clearing takes at least self.depth + 2 cycles.
    """

    _P = CountHashTab._P

    def __init__(
        self,
        *,
        depth: int,
        width: int,
        counter_width: int,
        input_data_width: int,
        hash_params: list[tuple[int, int]] | None = None,
    ) -> None:
        if depth < 1:
            raise ValueError("depth must be ≥ 1")

        self.depth = depth
        self.width = width
        self.counter_width = counter_width
        self.input_data_width = input_data_width

        self.insert = Method(i=[("data", self.input_data_width)])
        self.query_req = Method(i=[("data", self.input_data_width)])
        self.query_resp = Method(o=[("count", self.counter_width), ("valid", 1)])
        self.clear = Method()

        self.rows: list[CountHashTab] = []
        for idx in range(depth):
            a, b = hash_params[idx] if hash_params is not None else (idx + 1, 0)
            row = CountHashTab(
                size=width,
                counter_width=counter_width,
                input_data_width=input_data_width,
                hash_a=a,
                hash_b=b,
            )
            setattr(self, f"_row{idx}", row)
            self.rows.append(row)

    def elaborate(self, platform):
        m = TModule()
        m.submodules += self.rows

        @def_method(m, self.insert)
        def _(data):
            for row in self.rows:
                row.insert(m, data=data)

        min_tree = [Signal(self.counter_width) for _ in range(2 * self.depth)]

        @def_method(m, self.query_resp)
        def _():
            row_results = [row.query_resp(m) for row in self.rows]
            count_signals = [r["count"] for r in row_results]

            for i in range(len(count_signals)):
                m.d.comb += min_tree[self.depth + i].eq(count_signals[i])
            for i in range(1, self.depth):
                m.d.comb += min_tree[i].eq(
                    Mux(
                        min_tree[2 * i] < min_tree[2 * i + 1],
                        min_tree[2 * i],
                        min_tree[2 * i + 1],
                    )
                )

            return {"count": min_tree[1], "valid": row_results[0]["valid"]}

        @def_method(m, self.query_req)
        def _(data):
            for row in self.rows:
                row.query_req(m, data=data)

        @def_method(m, self.clear)
        def _():
            for row in self.rows:
                row.clear(m)

        return m
