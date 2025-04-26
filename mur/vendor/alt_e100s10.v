module alt_e100s10 (
      ///////// CLOCK /////////
      input              CLK_100_B3I,
      input              CLK_50_B2C,
      input              CLK_50_B2L,
      input              CLK_50_B3C,
      input              CLK_50_B3I,
      input              CLK_50_B3L,

      ///////// Buttons /////////
      input              CPU_RESET_n,
      input    [ 1: 0]   BUTTON,

      ///////// Switches /////////
      input    [ 1: 0]   SW,

      ///////// LED /////////
      output   [ 3: 0]   LED, // LED is Low-Active

      ///////// FLASH /////////
      output             FLASH_CLK,
      output   [27: 1]   FLASH_A,
      inout    [15: 0]   FLASH_D,
      output             FLASH_CE_n,
      output             FLASH_WE_n,
      output             FLASH_OE_n,
      output             FLASH_ADV_n,
      output             FLASH_RESET_n,
      input              FLASH_RDY_BSY_n,

      ///////// QSFP28A /////////
      input              QSFP28A_REFCLK_p,
      output   [ 3: 0]   QSFP28A_TX_p,
      input    [ 3: 0]   QSFP28A_RX_p,
      input              QSFP28A_INTERRUPT_n,
      output             QSFP28A_LP_MODE,
      input              QSFP28A_MOD_PRS_n,
      output             QSFP28A_MOD_SEL_n,
      output             QSFP28A_RST_n,
      inout              QSFP28A_SCL,
      inout              QSFP28A_SDA,

      ///////// SI5340A0 /////////
      inout              SI5340A0_I2C_SCL,
      inout              SI5340A0_I2C_SDA,
      input              SI5340A0_INTR,
      output             SI5340A0_OE_n,
      output             SI5340A0_RST_n,

      ///////// SI5340A1 /////////
      inout              SI5340A1_I2C_SCL,
      inout              SI5340A1_I2C_SDA,
      input              SI5340A1_INTR,
      output             SI5340A1_OE_n,
      output             SI5340A1_RST_n,

      ///////// I2Cs /////////
      inout              FAN_I2C_SCL,
      inout              FAN_I2C_SDA,
      input              FAN_ALERT_n,
      inout              POWER_MONITOR_I2C_SCL,
      inout              POWER_MONITOR_I2C_SDA,
      input              POWER_MONITOR_ALERT_n,
      inout              TEMP_I2C_SCL,
      inout              TEMP_I2C_SDA,

      ///////// GPIO /////////
      inout    [ 1: 0]   GPIO_CLK,
      inout    [ 3: 0]   GPIO_P,

      ///////// EXP /////////
      input              EXP_EN,

      ///////// UFL /////////
      inout              UFL_CLKIN_p,
      inout              UFL_CLKIN_n
);

//------------------------------------------------------------------------------
// Basic Signals
//------------------------------------------------------------------------------
wire        clk50      = CLK_50_B2C;
wire        cpu_resetn = CPU_RESET_n;
wire [7:0]  user_led;
assign      LED        = user_led[3:0];
assign      user_led   = 8'b0;

// QSFP signals
wire        qsfp_rstn;
wire        qsfp_lowpwr;
wire        clk_ref_r;
wire [3:0]  rx_serial;
wire [3:0]  tx_serial;

assign QSFP28A_RST_n   = qsfp_rstn;
assign QSFP28A_LP_MODE = qsfp_lowpwr;
assign clk_ref_r       = QSFP28A_REFCLK_p;
assign QSFP28A_TX_p    = tx_serial;
assign rx_serial       = QSFP28A_RX_p;

assign qsfp_rstn       = 1'b1;
assign qsfp_lowpwr     = 1'b0;

// Si5340 signals
assign SI5340A0_RST_n  = 1'b1;
assign SI5340A1_RST_n  = 1'b1;
assign SI5340A0_OE_n   = 1'b0;
assign SI5340A1_OE_n   = 1'b0;

//------------------------------------------------------------------------------
// System PLL
//------------------------------------------------------------------------------
wire        iopll_locked;
wire        clk100;
alt_e100s10_sys_pll u0 (
    .rst        (~cpu_resetn),
    .refclk     (clk50),
    .locked     (iopll_locked),
    .outclk_0   (clk100)
);

//------------------------------------------------------------------------------
// 100G Ethernet IP
//------------------------------------------------------------------------------
wire [15:0] status_addr;
wire        status_read, status_write;
wire        status_readdata_valid_eth;
wire [31:0] status_readdata_eth, status_writedata;
wire        clk_status = clk100;

wire        clk_txmac;    
wire        clk_rxmac;    

wire        tx_lanes_stable;
wire        rx_pcs_ready;
wire        rx_block_lock;
wire        rx_am_lock;
wire        txstatus_valid, txstatus_error;

// Reconfig signals
wire        reco_write, reco_read;
wire [31:0] reco_readdata;
wire        reco_waitrequest;
wire [15:0] reco_addr; 

// ATX PLL
wire serial_clk_1;
wire pll_locked_1;
wire serial_clk_2;
wire pll_locked_2;
wire [1:0] pll_locked;

atx_pll_s100 atx1 (
    .pll_refclk0      (clk_ref_r),
    .tx_serial_clk_gxt(serial_clk_1),
    .pll_locked       (pll_locked_1),
    .pll_cal_busy     ()
);

atx_pll_s100 atx2 (
    .pll_refclk0      (clk_ref_r),
    .tx_serial_clk_gxt(serial_clk_2),
    .pll_locked       (pll_locked_2),
    .pll_cal_busy     ()
);

assign pll_locked = {pll_locked_1, pll_locked_2};

//
// 100G IP instance
//
wire [511:0] l8_tx_data;
wire [5:0]   l8_tx_empty;
wire         l8_tx_endofpacket;
wire         l8_tx_startofpacket;
wire         l8_tx_valid;
wire         l8_tx_ready;

wire [511:0] l8_rx_data;
wire [5:0]   l8_rx_empty;
wire         l8_rx_endofpacket;
wire         l8_rx_startofpacket;
wire         l8_rx_valid;
wire [5:0]   l8_rx_error;

ex_100g ex_100g_inst (
    .clk_ref                (clk_ref_r),
    .csr_rst_n              (1'b1),
    .tx_rst_n               (1'b1),
    .rx_rst_n               (1'b1),
    .clk_status             (clk_status),
    .status_write           (status_write),
    .status_read            (status_read),
    .status_addr            (status_addr),
    .status_writedata       (status_writedata),
    .status_readdata        (status_readdata_eth),
    .status_readdata_valid  (status_readdata_valid_eth),
    .status_waitrequest     (),

    .clk_txmac              (clk_txmac),
    .l8_tx_startofpacket    (l8_tx_startofpacket),
    .l8_tx_endofpacket      (l8_tx_endofpacket),
    .l8_tx_valid            (l8_tx_valid),
    .l8_tx_ready            (l8_tx_ready),
    .l8_tx_empty            (l8_tx_empty),
    .l8_tx_data             (l8_tx_data),
    .l8_tx_error            (1'b0),

    .clk_rxmac              (clk_rxmac),
    .l8_rx_error            (l8_rx_error),
    .l8_rx_valid            (l8_rx_valid),
    .l8_rx_startofpacket    (l8_rx_startofpacket),
    .l8_rx_endofpacket      (l8_rx_endofpacket),
    .l8_rx_empty            (l8_rx_empty),
    .l8_rx_data             (l8_rx_data),

    .tx_serial              (tx_serial),
    .rx_serial              (rx_serial),

    // Reconfig
    .reconfig_clk           (clk_status),
    .reconfig_reset         (1'b0),
    .reconfig_write         (reco_write),
    .reconfig_read          (reco_read),
    .reconfig_address       (reco_addr),
    .reconfig_writedata     (status_writedata),
    .reconfig_readdata      (reco_readdata),
    .reconfig_waitrequest   (reco_waitrequest),

    .tx_lanes_stable        (tx_lanes_stable),
    .rx_pcs_ready           (rx_pcs_ready),
    .rx_block_lock          (rx_block_lock),
    .rx_am_lock             (rx_am_lock),
    .l8_txstatus_valid      (txstatus_valid),
    .l8_txstatus_data       (),
    .l8_txstatus_error      (txstatus_error),
    .l8_rxstatus_valid      (),
    .l8_rxstatus_data       (),
    .tx_serial_clk          ({serial_clk_2, serial_clk_1}),
    .tx_pll_locked          (pll_locked)
);

//------------------------------------------------------------------------------
// 1) First Async FIFO: RX domain -> "modification" domain
//    Data format = 520 bits total:
//      [519]     = SOP
//      [518]     = EOP
//      [517:512] = EMPTY[5:0]
//      [511:0]   = DATA
//------------------------------------------------------------------------------
localparam FIFO_DATA_WIDTH = 520;  // 1 + 1 + 6 + 512
localparam FIFO_DEPTH      = 64;   // Must be power of 2

wire [FIFO_DATA_WIDTH-1:0] fifo1_wr_data;
wire                       fifo1_wr_en;
wire                       fifo1_full;

wire [FIFO_DATA_WIDTH-1:0] fifo1_rd_data;
wire                       fifo1_rd_en;
wire                       fifo1_rd_valid;
wire                       fifo1_empty;

assign fifo1_wr_en = l8_rx_valid;
assign fifo1_wr_data = {
    l8_rx_startofpacket,  // [519]
    l8_rx_endofpacket,    // [518]
    l8_rx_empty,          // [517:512]
    l8_rx_data            // [511:0]
};

async_fifo #(
    .DATA_WIDTH (FIFO_DATA_WIDTH),
    .DEPTH      (FIFO_DEPTH)
) u_fifo_rx2mod (
    // Write side: RX domain
    .wr_clk     (clk_rxmac),
    .wr_rst_n   (cpu_resetn),
    .wr_data    (fifo1_wr_data),
    .wr_en      (fifo1_wr_en),
    .wr_full    (fifo1_full),

    // Read side: mod_clk domain
    .rd_clk     (clk100),
    .rd_rst_n   (cpu_resetn),
    .rd_data    (fifo1_rd_data),
    .rd_en      (fifo1_rd_en),
    .rd_valid   (fifo1_rd_valid),
    .rd_empty   (fifo1_empty)
);

//------------------------------------------------------------------------------
// 2) Placeholder Module (runs at clk100 domain):
//    - Reads from FIFO #1
//    - Simple modification: increment the DATA field by 1
//    - Writes to FIFO #2
//------------------------------------------------------------------------------
wire [FIFO_DATA_WIDTH-1:0] fifo2_wr_data;
wire                       fifo2_wr_en;
wire                       fifo2_full;

wire [FIFO_DATA_WIDTH-1:0] fifo2_rd_data;
wire                       fifo2_rd_en;
wire                       fifo2_rd_valid;
wire                       fifo2_empty;

placeholder_module #(
    .DATA_WIDTH (FIFO_DATA_WIDTH)
) u_placeholder_mod (
    .clk        (clk100),
    .rst_n      (cpu_resetn),

    // FIFO #1 read side
    .in_data    (fifo1_rd_data),
    .in_valid   (fifo1_rd_valid), // we rely on rd_valid from FIFO #1
    .in_empty   (fifo1_empty),    // not strictly needed if we have in_valid
    .rd_en_fifo (fifo1_rd_en),

    // FIFO #2 write side
    .out_data   (fifo2_wr_data),
    .wr_en_fifo (fifo2_wr_en),
    .out_full   (fifo2_full)
);

//------------------------------------------------------------------------------
// 3) Second Async FIFO: modification domain -> TX domain
//------------------------------------------------------------------------------
async_fifo #(
    .DATA_WIDTH (FIFO_DATA_WIDTH),
    .DEPTH      (FIFO_DEPTH)
) u_fifo_mod2tx (
    // Write side: mod_clk domain
    .wr_clk     (clk100),
    .wr_rst_n   (cpu_resetn),
    .wr_data    (fifo2_wr_data),
    .wr_en      (fifo2_wr_en),
    .wr_full    (fifo2_full),

    // Read side: TX domain
    .rd_clk     (clk_txmac),
    .rd_rst_n   (cpu_resetn),
    .rd_data    (fifo2_rd_data),
    .rd_en      (fifo2_rd_en),
    .rd_valid   (fifo2_rd_valid),
    .rd_empty   (fifo2_empty)
);

//------------------------------------------------------------------------------
// 4) TX Domain: reads from FIFO #2, same "store-and-send" logic as before
//------------------------------------------------------------------------------
localparam MAX_BEATS = 64;
reg [FIFO_DATA_WIDTH-1:0] packet_mem_tx [0:MAX_BEATS-1];

reg [1:0]  tx_state, tx_next_state;
localparam TX_IDLE = 2'd0;
localparam TX_LOAD = 2'd1;  // read from FIFO #2 until EOP
localparam TX_SEND = 2'd2;
localparam TX_DONE = 2'd3;

reg [6:0]  load_ptr;
reg [6:0]  load_len;
reg [6:0]  tx_rd_ptr;

// Decompose the FIFO #2 data
wire rd_sop        = fifo2_rd_data[519];
wire rd_eop        = fifo2_rd_data[518];
wire [5:0] rd_empty_bits = fifo2_rd_data[517:512];
wire [511:0] rd_data_bits  = fifo2_rd_data[511:0];

always @(*) begin
    tx_next_state = tx_state;
    case (tx_state)
        TX_IDLE: begin
            if (tx_lanes_stable && !fifo2_empty) begin
                tx_next_state = TX_LOAD;
            end
        end
        TX_LOAD: begin
            if (fifo2_rd_valid && rd_eop) begin
                tx_next_state = TX_SEND;
            end
        end
        TX_SEND: begin
            if (l8_tx_ready && (tx_rd_ptr == (load_len - 1))) begin
                tx_next_state = TX_DONE;
            end
        end
        TX_DONE: begin
            tx_next_state = TX_IDLE;
        end
    endcase
end

always @(posedge clk_txmac or negedge cpu_resetn) begin
    if (!cpu_resetn) begin
        tx_state  <= TX_IDLE;
        load_ptr  <= 7'd0;
        load_len  <= 7'd0;
        tx_rd_ptr <= 7'd0;
    end else begin
        tx_state <= tx_next_state;
        case (tx_state)
            TX_IDLE: begin
                load_ptr  <= 0;
                load_len  <= 0;
                tx_rd_ptr <= 0;
            end
            TX_LOAD: begin
                if (fifo2_rd_valid) begin
                    packet_mem_tx[load_ptr] <= fifo2_rd_data;
                    load_ptr <= load_ptr + 1'b1;
                    if (rd_eop) begin
                        load_len <= load_ptr + 1'b1;
                    end
                end
            end
            TX_SEND: begin
                if (l8_tx_ready) begin
                    tx_rd_ptr <= tx_rd_ptr + 1'b1;
                end
            end
            TX_DONE: begin
                // Goes back to IDLE
            end
        endcase
    end
end

// FIFO #2 read enable
assign fifo2_rd_en = (tx_state == TX_LOAD) && !fifo2_empty;

// Drive l8_tx_* signals
wire [FIFO_DATA_WIDTH-1:0] this_beat = packet_mem_tx[tx_rd_ptr];

wire this_sop       = this_beat[519];
wire this_eop       = this_beat[518];
wire [5:0] this_empty  = this_beat[517:512];
wire [511:0] this_data = this_beat[511:0];

assign l8_tx_valid         = (tx_state == TX_SEND);
assign l8_tx_startofpacket = (tx_state == TX_SEND) && (tx_rd_ptr == 0);
assign l8_tx_endofpacket   = (tx_state == TX_SEND) && (tx_rd_ptr == (load_len - 1));

// If final beat, use stored empty bits; else 0
assign l8_tx_empty = (tx_state == TX_SEND && tx_rd_ptr == (load_len - 1))
                   ? this_empty
                   : 6'd0;

assign l8_tx_data = (tx_state == TX_SEND)
                  ? this_data
                  : 512'd0;

endmodule

module placeholder_module #(
    parameter DATA_WIDTH = 520
)(
    input                       clk,
    input                       rst_n,

    // FIFO #1 read side
    input      [DATA_WIDTH-1:0] in_data,    // data from FIFO #1
    input                       in_valid,   // indicates in_data is valid this cycle
    input                       in_empty,   // indicates FIFO #1 is empty
    output reg                  rd_en_fifo, // read-enable for FIFO #1

    // FIFO #2 write side
    output reg [DATA_WIDTH-1:0] out_data,   // data to FIFO #2
    output reg                  wr_en_fifo, // write-enable for FIFO #2
    input                       out_full    // indicates FIFO #2 is full
);

    // Decompose fields for readability
    wire sop_in        = in_data[519];
    wire eop_in        = in_data[518];
    wire [5:0] empty_in= in_data[517:512];
    wire [511:0] dat_in= in_data[511:0];

    // 1) We'll only assert rd_en_fifo if we do NOT have data valid 
    //    (i.e., in_valid == 0) and FIFO #1 is not empty, and FIFO #2 is not full.
    // 2) On the cycle in_valid is high, we drive out_data and wr_en_fifo.

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rd_en_fifo <= 1'b0;
            wr_en_fifo <= 1'b0;
            out_data   <= {DATA_WIDTH{1'b0}};
        end else begin
            // Default: no read, no write this cycle
            rd_en_fifo <= 1'b0;
            wr_en_fifo <= 1'b0;

            // If we currently don't have valid data (in_valid=0),
            // but FIFO #1 is not empty, and FIFO #2 is not full,
            // request new data from FIFO #1
            if (!in_valid && !in_empty && !out_full) begin
                rd_en_fifo <= 1'b1;
            end

            // If in_valid is high, that means we have stable data from FIFO #1 
            // in this cycle. We can modify and write to FIFO #2 if it's not full.
            if (in_valid && !out_full) begin
                // Modify data (add 1 to 512-bit field)
                out_data <= {
                    sop_in,          // pass SOP
                    eop_in,          // pass EOP
                    empty_in,        // pass EMPTY
                    (dat_in + 512'd1)
                };
                wr_en_fifo <= 1'b1;
            end
        end
    end

endmodule


//============================================================
// Custom Asynchronous FIFO (Dual-clock FIFO)
// with Gray-coded pointers.
//
// Parameterized for data width and depth. 
// For large depth, consider block RAM or vendor IP.
//
//============================================================
module async_fifo #(
    parameter DATA_WIDTH = 520,
    parameter DEPTH      = 64    // must be power-of-2
)(
    // Write interface
    input                      wr_clk,
    input                      wr_rst_n,
    input  [DATA_WIDTH-1 : 0]  wr_data,
    input                      wr_en,
    output                     wr_full,

    // Read interface
    input                      rd_clk,
    input                      rd_rst_n,
    output [DATA_WIDTH-1 : 0]  rd_data,
    input                      rd_en,
    output                     rd_valid,
    output                     rd_empty
);

    localparam ADDR_WIDTH = $clog2(DEPTH);

    // Memory
    reg [DATA_WIDTH-1:0] mem [0:DEPTH-1];

    // Write pointers (binary & gray)
    reg [ADDR_WIDTH:0] wr_ptr_bin, wr_ptr_bin_nxt;
    reg [ADDR_WIDTH:0] wr_ptr_gray, wr_ptr_gray_nxt;

    // Read pointers (binary & gray)
    reg [ADDR_WIDTH:0] rd_ptr_bin, rd_ptr_bin_nxt;
    reg [ADDR_WIDTH:0] rd_ptr_gray, rd_ptr_gray_nxt;

    // Synchronizers
    reg [ADDR_WIDTH:0] rd_ptr_gray_sync1, rd_ptr_gray_sync2;
    reg [ADDR_WIDTH:0] wr_ptr_gray_sync1, wr_ptr_gray_sync2;

    // Read data pipeline
    reg [DATA_WIDTH-1:0] rd_data_reg;
    reg                  rd_valid_reg;

    //---------------------------
    //  Write-Side Logic
    //---------------------------
    always @(*) begin
        wr_ptr_bin_nxt = wr_ptr_bin;
        if (wr_en && !wr_full) begin
            wr_ptr_bin_nxt = wr_ptr_bin + 1'b1;
        end
    end

    // Gray conversion
    always @(*) begin
        wr_ptr_gray_nxt = wr_ptr_bin_nxt ^ (wr_ptr_bin_nxt >> 1);
    end

    // Write pointer registers
    always @(posedge wr_clk or negedge wr_rst_n) begin
        if (!wr_rst_n) begin
            wr_ptr_bin  <= 0;
            wr_ptr_gray <= 0;
        end else begin
            wr_ptr_bin  <= wr_ptr_bin_nxt;
            wr_ptr_gray <= wr_ptr_gray_nxt;
        end
    end

    // Write memory
    always @(posedge wr_clk) begin
        if (wr_en && !wr_full) begin
            mem[wr_ptr_bin[ADDR_WIDTH-1:0]] <= wr_data;
        end
    end

    // Sync read pointer (gray) into write domain
    always @(posedge wr_clk or negedge wr_rst_n) begin
        if (!wr_rst_n) begin
            rd_ptr_gray_sync1 <= 0;
            rd_ptr_gray_sync2 <= 0;
        end else begin
            rd_ptr_gray_sync1 <= rd_ptr_gray;
            rd_ptr_gray_sync2 <= rd_ptr_gray_sync1;
        end
    end

    // Convert synchronized read pointer from Gray to Binary
    wire [ADDR_WIDTH:0] rd_ptr_bin_sync = gray2bin(rd_ptr_gray_sync2);

    // Full detection for 2^ADDR_WIDTH-depth FIFO
    wire [ADDR_WIDTH:0] wr_ptr_bin_next = wr_ptr_bin_nxt;
    wire [ADDR_WIDTH:0] wr_ptr_bin_sync = rd_ptr_bin_sync;
    reg full_reg;

    wire fifo_full_val =
       (wr_ptr_bin_next[ADDR_WIDTH]     != wr_ptr_bin_sync[ADDR_WIDTH]) &&
       (wr_ptr_bin_next[ADDR_WIDTH-1:0] == wr_ptr_bin_sync[ADDR_WIDTH-1:0]);

    always @(posedge wr_clk or negedge wr_rst_n) begin
        if (!wr_rst_n)
            full_reg <= 1'b0;
        else
            full_reg <= fifo_full_val;
    end

    assign wr_full = full_reg;

    //---------------------------
    //  Read-Side Logic
    //---------------------------
    always @(*) begin
        rd_ptr_bin_nxt = rd_ptr_bin;
        if (rd_en && !rd_empty) begin
            rd_ptr_bin_nxt = rd_ptr_bin + 1'b1;
        end
    end

    // Convert to Gray
    always @(*) begin
        rd_ptr_gray_nxt = rd_ptr_bin_nxt ^ (rd_ptr_bin_nxt >> 1);
    end

    // Update read pointer
    always @(posedge rd_clk or negedge rd_rst_n) begin
        if (!rd_rst_n) begin
            rd_ptr_bin  <= 0;
            rd_ptr_gray <= 0;
        end else begin
            rd_ptr_bin  <= rd_ptr_bin_nxt;
            rd_ptr_gray <= rd_ptr_gray_nxt;
        end
    end

    // Memory read (registered)
    reg [DATA_WIDTH-1:0] mem_q;
    always @(posedge rd_clk) begin
        mem_q <= mem[rd_ptr_bin_nxt[ADDR_WIDTH-1:0]];
    end

    // Registered outputs
    always @(posedge rd_clk or negedge rd_rst_n) begin
        if (!rd_rst_n) begin
            rd_valid_reg <= 1'b0;
            rd_data_reg  <= {DATA_WIDTH{1'b0}};
        end else begin
            // Valid if we performed a read
            rd_valid_reg <= (rd_en && !rd_empty);
            rd_data_reg  <= mem_q;
        end
    end

    assign rd_valid = rd_valid_reg;
    assign rd_data  = rd_data_reg;

    // Sync write pointer (gray) into read domain
    always @(posedge rd_clk or negedge rd_rst_n) begin
        if (!rd_rst_n) begin
            wr_ptr_gray_sync1 <= 0;
            wr_ptr_gray_sync2 <= 0;
        end else begin
            wr_ptr_gray_sync1 <= wr_ptr_gray;
            wr_ptr_gray_sync2 <= wr_ptr_gray_sync1;
        end
    end

    // Convert synchronized write pointer from Gray to binary
    wire [ADDR_WIDTH:0] wr_ptr_bin_sync2 = gray2bin(wr_ptr_gray_sync2);

    // Empty detection
    reg empty_reg;
    wire [ADDR_WIDTH:0] rd_ptr_bin_next2 = rd_ptr_bin_nxt;
    wire fifo_empty_val = (rd_ptr_bin_next2 == wr_ptr_bin_sync2);

    always @(posedge rd_clk or negedge rd_rst_n) begin
        if (!rd_rst_n)
            empty_reg <= 1'b1;
        else
            empty_reg <= fifo_empty_val;
    end

    assign rd_empty = empty_reg;

    //---------------------------
    // Gray->Binary function
    //---------------------------
    function [ADDR_WIDTH:0] gray2bin(input [ADDR_WIDTH:0] g);
        integer i;
        reg [ADDR_WIDTH:0] b;
    begin
        b[ADDR_WIDTH] = g[ADDR_WIDTH];
        for (i = ADDR_WIDTH-1; i >= 0; i=i-1) begin
            b[i] = b[i+1] ^ g[i];
        end
        gray2bin = b;
    end
    endfunction

endmodule
