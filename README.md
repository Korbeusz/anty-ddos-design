# Module Overview – DDoS‑Filtering Hardware Design

This markdown file walks through every significant Python/Amaranth RTL module in the *mur* project and explains how each piece contributes to a **line‑rate DDoS‑mitigation pipeline**.  The design parses packets, measures flow statistics, decides whether to pass or drop them to identify volumetric or flood attacks in real time.

---

## 1  Packet Parsing & Alignment

| Stage        | Module / Class                                       | Purpose                                                                                                                                                                                                                                                    |
| ------------ | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aligner**  | `extract/aligner.py` → **`ParserAligner`**           | Re‑assembles mis‑aligned 64‑byte words between successive protocol parsers so that every downstream block always sees its header starting at bit‑0. Keeps “straddled” tail bytes in a small buffer and injects them into the next cycle.|
| **Ethernet** | `extract/parsers/ethernet.py` → **`EthernetParser`** | Extracts destination/source MAC, optional VLAN tag, EtherType and decides whether the next header is IPv4/IPv6/ARP. Drops runt (<14 B) frames.                                                                                          |
| **IPv4**     | `extract/parsers/ipv4_parser.py` → **`IPv4Parser`**  | Validates IPv4 minimum length, parses the L3 header and outputs protocol ID + total length. Also classifies unknown or malformed packets for early discard.                                                                        |
| **TCP**      | `extract/parsers/tcp.py` → **`TCPParser`**           | Reads the first 20 bytes of a TCP header (ports, seq/ack, flags…) and reports the destination port so the sketch can learn *TCP SYN flood* hotspots. Detects runt or truncated headers.                                               |
| **UDP**      | `extract/parsers/udp.py` → **`UDPParser`**           | Mirrors the TCP block for UDP: grabs src/dst ports and length, flags packets shorter than 8 bytes, and feeds destination‑port entropy into the sketch.                                                                                  |

These five blocks are wired in *parse → align → parse* fashion by the top‑level pipeline to create a **feature vector** ⟨src‑IP, dst‑IP, dst‑port, tot‑len⟩ for every well‑formed IPv4/TCP/UDP packet.

---

## 2  Statistical Counters

| Component                 | Module / Class                   | DDoS‑relevance                                                                                                                                                                                                       |
| ------------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CountHashTab**          | `count/CountHashTab.py`          | A single‑row array of saturating counters with a 1‑cycle pipelined multiply‑with‑prime hash. Forms the physical storage of one Count‑Min row.                                                    |
| **CountMinSketch**        | `count/CountMinSketch.py`        | Wraps *depth* independent `CountHashTab`s and returns the **minimum** across rows, giving a low‑overhead cardinality estimate per key. Supports *insert*, *query* and *clear*.                   |
| **RollingCountMinSketch** | `count/RollingCountMinSketch.py` | Maintains three sketches that rotate roles (UPDATE → QUERY → CLEAR) so estimates age out automatically, yielding a *sliding‑window* view crucial for detecting bursts.                        |
| **VolCounter**            | `count/VolCounter.py`            | Simple accumulator over a configurable window that flags when byte‑volume exceeds a threshold – a heuristic to switch the sketches between **learning** and **probing** modes when traffic spikes. |
| **CMSVolController**      | `count/CMSVolController.py`      | Supervises three Rolling‑CMS instances keyed on ⟨SIP‖DIP⟩, ⟨DIP‖DPORT⟩, ⟨SIP‖LEN⟩ and couples them with *VolCounter*. Outputs: *how many packets of the current burst to forward* (or 0 → drop).    |

Together they implement a **multi‑dimensional heavy‑hitter detector**.

---

## 3  Integrated Pipeline

### `final_build/ParserCMSVol.py` → **ParserCMSVol**

Top‑level RTL that chains all parsers, both aligners and the `CMSVolController`. It converts each accepted packet into four FIFO pushes for the controller, pulls the controller’s numeric *pass/drop decision*, and streams only the permitted packets to its `dout` port. Effectively this is the **hardware DDoS filter** that can be instantiated in an FPGA datapath.

---
