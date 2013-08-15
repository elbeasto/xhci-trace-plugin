"""
	Trace-cmd plugin for xHCI host controller driver

	Copyright (C) 2013 Xenia Ragiadakou

	Email : burzalodowa@gmail.com

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License Version 2 as
	published by the Free Software Foundation.
"""

import tracecmd
from struct import unpack

def get_slot_state(code):
    states = {
        0 : "Disabled",
        1 : "Default",
        2 : "Addressed",
        3 : "Configured"
        }

    if code in states:
        return states[code]
    else:
        return "Reserved"

def get_ep_state(code):
    states = {
        0 : "Disabled",
        1 : "Running",
        2 : "Halted",
        3 : "Stopped",
        4 : "Error"
        }

    if code in states:
        return states[code]
    else:
        return "Reserved"

def parse_ctx_field(name, d):
    fields = {
        "dev_info": "[Route=0x%x][Speed=%d][MTT=%d][Hub=%d][CtxEntries=%d]" %
        (d & 0xfffff, (d>>20) & 0xf, (d>>25) & 0x1, (d>>26) & 0x1, d >> 27),
        "dev_info2": "[MaxExitLat=%d][RHPort=%d][PortsNum=%d]" %
        (d & 0xffff, (d>>16) & 0xff, (d>>24) & 0xff),
        "tt_info": "[TTHubSlot=%d][TTPort=%d][TTT=%d][IntrTarget=%d]" %
        (d & 0xff, (d>>8) & 0xff, (d>>16) & 0x3, d >> 22),
        "dev_state": "[DevAddr=%x][SlotState=%s]" %
        (d & 0xff, get_slot_state(d >> 27)),
        "ep_info": "[EpState=%s][Mult=%d][MaxPStreams=%d][LSA=%d][Interval=%d]"%
        (get_ep_state(d & 0x7), (d>>8) & 0x3, (d>>10) & 0x1f, (d>>15) & 0x1,
         (d>>16) & 0xff),
        "ep_info2": "[CErr=%d][Type=%d][HID=%d][MaxBurstSz=%d][MaxPackSz=%d]" %
        ((d>>1) & 0x3, (d>>3) & 0x7, (d>>7) & 0x1, (d>>8) & 0xff, d >> 16),
        "deq": "[DCS=%d][TRDeqPtr=0x%x]" % (d & 0x1, (d>>4) << 4),
        "tx_info": "[AvgTRBLen=%d][MaxESITPayload=%d]" % (d & 0xffff, d >> 16)
        }

    if name in fields:
        return fields[name]
    else:
        return ""

def add_ctx_entry(l, field, data):
    dma, va, i = l[-1][1:]
    parsed_field = parse_ctx_field(field, data[i])
    ctx_entry = ("%-10s\t0x%08x\t@%08x\t@%08x\t%s\n" %
                 (field, data[i], dma, va, parsed_field))
    if field != "deq" and field.find("rsvd64") < 0:
        dma += 4
        va += 4
    else:
        dma += 8
        va += 8
    i += 1
    l.append([ctx_entry, dma, va, i])


def xhci_ctx_handler(trace_seq, event):
    """
    Parse the data in the xhci_container_ctx structure and print the field
    values and addresses of Device Context and Input Context data structures.
    """

    slot_id = int(event['slot_id'])
    ctx_dma = long(event['ctx_dma'])
    ctx_va = long(event['ctx_va'])
    ctx_ep_num = int(event['ctx_ep_num'])

    ctx_is_64bytes = int(event['ctx_64'])
    ctx_type_is_device = int(event['ctx_type']) == 0x1
    ctx_type_is_input = int(event['ctx_type']) == 0x2

    if ctx_type_is_device:
        direction = "Output";
        if ctx_is_64bytes:
            ctx_data_fmt = "<8I4Q" + "2IQ4I4Q"*ctx_ep_num
        else:
            ctx_data_fmt = "<8I" + "2IQ4I"*ctx_ep_num
    elif ctx_type_is_input:
        direction = "Input"
        if ctx_is_64bytes:
            ctx_data_fmt = "<8I4Q8I4Q" + "2IQ4I4Q"*ctx_ep_num
        else:
            ctx_data_fmt = "<8I8I" + "2IQ4I"*ctx_ep_num
    else:
        trace_seq.puts("\nUnknown context type: %d\n" % int(event['ctx_type']))
        return

    ctx_bytes = unpack(ctx_data_fmt, event['ctx_data'].data)
    label = "%-10s\t%-10s\t%-9s\t%s\n" % ("Field", "Value", "DMA", "Virtual")
    rsvd = [("rsvd" + str(i)) for i in range(6)]
    cntl_fields = ["drop_flags", "add_flags"] + rsvd
    slot_fields = ["dev_info", "dev_info2", "tt_info", "dev_state"] + rsvd[:4]
    ep_fields = ["ep_info", "ep_info2", "deq", "tx_info"] + rsvd[:3]

    l = [["", ctx_dma, ctx_va, 0]];
    if ctx_type_is_input:
        l[-1][0] += "\nInput Control Context:\n\n" + label
        [add_ctx_entry(l, cntl_fields[j], ctx_bytes) for j in range(8)]
        if ctx_is_64bytes:
            [add_ctx_entry(l, "rsvd64[%d]" % j, ctx_bytes) for j in range(4)]

    l[-1][0] += "\nSlot ID %d %s Context:\n\n%s" % (slot_id, direction, label)
    [add_ctx_entry(l, slot_fields[j], ctx_bytes) for j in range(8)]
    if ctx_is_64bytes:
            [add_ctx_entry(l, "rsvd64[%d]" % j, ctx_bytes) for j in range(4)]

    for ep in range(ctx_ep_num):
        l[-1][0] += "\nEndpoint %d %s Context:\n\n%s" % (ep, direction, label)
        [add_ctx_entry(l, ep_fields[j], ctx_bytes) for j in range(7)]
        if ctx_is_64bytes:
            [add_ctx_entry(l, "rsvd64[%d]" % j, ctx_bytes) for j in range(4)]

    [trace_seq.puts(t[0]) for t in l]


def get_compl_code_str(code):
    """
    Return a stringified version of the command completion code.
    """

    compl_codes = { 0  : "Invalid",
                    1  : "Success",
                    2  : "Data Buffer Error ",
                    3  : "Babble Detected Error",
                    4  : "USB Transaction Error",
                    5  : "TRB Error",
                    6  : "Stall Error",
                    7  : "Resource Error",
                    8  : "Bandwidth Error",
                    9  : "No Slots Available Error",
                    10 : "Invalid Stream Type Error",
                    11 : "Slot Not Enabled Error",
                    12 : "Endpoint Not Enabled Error",
                    13 : "Short Packet",
                    14 : "Ring Underrun",
                    15 : "Ring Overrun",
                    16 : "VF Event Ring Full Error",
                    17 : "Parameter Error",
                    18 : "Bandwidth Overrun Error",
                    19 : "Context State Error",
                    20 : "No Ping Response Error",
                    21 : "Event Ring Full Error",
                    22 : "Incompatible Device Error",
                    23 : "Missed Service Error",
                    24 : "Command Ring Stopped",
                    25 : "Command Aborted",
                    26 : "Stopped",
                    27 : "Stopped - Length Invalid",
                    29 : "Max Exit Latency Too Large Error",
                    31 : "Isoch Buffer Overrun",
                    32 : "Event Lost Error",
                    33 : "Undefined Error",
                    34 : "Invalid Stream ID Error",
                    35 : "Secondary Bandwidth Error",
                    36 : "Split Transaction Error" }

    if code in compl_codes:
        return compl_codes[code]
    else:
        return "Vendor specific"


def get_cmd_data(cmd):
    """
    Parse Command TRB depending on the type of the command
    and return a list with first element a string denoting
    the command type and second element a string with the
    remaining fields.
    """

    cmd_type = cmd[4] >> 2
    cmd_types = { 9  : ["Enable Slot Command", ""],
                  10 : ["Disable Slot Command", "[SlotID=%d]" % (cmd[6])],
                  11 : ["Address Device Command",
                        "[InputCtxPtr=%x][BSR=%d][SlotID=%d]" %
                        (cmd[0], (cmd[4]>>1) & 0x1, cmd[6])],
                  12 : ["Configure Endpoint Command",
                        "[InputCtxPtr=%x][DC=%d][SlotID=%d]" %
                        (cmd[0], (cmd[4]>>1) & 0x1, cmd[6])],
                  13 : ["Evaluate Context Command",
                        "[InputCtxPtr=%x][SlotID=%d]" % (cmd[0], cmd[6])],
                  14 : ["Reset Endpoint Command",
                        "[TSP=%d][EndpointID=%d][SlotID=%d]" %
                        ((cmd[4]>>1) & 0x1, cmd[5], cmd[6])],
                  15 : ["Stop Endpoint Command",
                        "[EpID=%d][SP=%d][SlotID=%d]" %
                        (cmd[5] & 0x1f, cmd[5] >> 7, cmd[6])],
                  16 : ["Set TR Dequeue Pointer Command",
                        "[DCS=%d][SCT=%d][TRDeqPtr=%x][StreamID=%d]"\
                            "[EpID=%d][SlotID=%d]" %
                        (cmd[0] & 0x1, (cmd[0]>>1) & 0x7, (cmd[0]>>4) << 4,
                         cmd[2], cmd[5], cmd[6])],
                  17 : ["Reset Device Command", "[SlotID=%d]" % (cmd[6])],
                  18 : ["Force Event Command",
                        "[EventTRBPtr=%x][VFIntrID=%d][VFID=%d]" %
                        (cmd[0], cmd[2] >> 8, cmd[5])],
                  19 : ["Negotiate Bandwidth Command",
                        "[SlotID=%d]" % (cmd[6])],
                  20 : ["Set Latency Tolerance Value Command",
                        "[BELT=%d]" % ((cmd[6]<<8) | cmd[5])],
                  21 : ["Get Port Bandwidth Command",
                        "[PortBwCtxPtr=%x][DevSpeed=%d][HubSlotID=%d]" %
                        (cmd[0], cmd[5], cmd[6])],
                  22 : ["Force Header Command", "[PacketType=%d][RHPort=%d]" %
                        (cmd[0] & 0x1f, cmd[6])],
                  23 : ["No Op Command", ""] }

    if cmd_type in cmd_types:
        return cmd_types[cmd_type]
    else:
        return ("Invalid Command Type", "Unknown")


def xhci_cmd_handler(trace_seq, event):
    """
    Print Command Completion Event fields and the associated Command TRB fields.
    """

    cmd_trb_dma = long(event['dma'])
    cmd_trb_va = long(event['va'])
    status = unpack("@4B", event['status'].data)
    flags = unpack("@4B", event['flags'].data)
    cmd_trb = unpack("<Q2H4B", event['trb'].data)

    compl_status = get_compl_code_str(status[3]);
    event_type = flags[1] >> 2
    vf_id = flags[2];
    slot_id = flags[3];
    cmd_data = get_cmd_data(cmd_trb)

    if event_type == 33:
        trace_seq.puts("Cmd Completion Event\n")
    else:
        return
    trace_seq.puts("%-10s:\t%s\n" % ("Cmd Type", cmd_data[0]))
    trace_seq.puts("%-10s:\t%s\n" % ("Status", compl_status))
    trace_seq.puts("%-10s:\t@%x\n" % ("DMA addr", cmd_trb_dma))
    trace_seq.puts("%-10s:\t@%x\n" % ("Virtual addr", cmd_trb_va))
    trace_seq.puts("%-10s:\t%i\n" % ("VF ID", vf_id))
    trace_seq.puts("%-10s:\t%i\n" % ("Slot ID", slot_id))
    trace_seq.puts("%-10s:\t%s\n" % ("Cmd Fields", cmd_data[1]))

def parse_normal_trb(tx_trb):
    trb = unpack("<QI2H", tx_trb.data)
    trb_str = '[DataBufferPtr=%x]' % trb[0]
    trb_str += '[TRBTxLen=%d]' % (trb[1] & 0x1ffff)
    trb_str += '[TDSize=%d]' % ((trb[1] >> 17) & 0x1f)
    trb_str += '[IntrTarget=%d]' % (trb[1] >> 22)
    trb_str += '[C=%d]' % (trb[2] & 1)
    trb_str += '[ENT=%d]' % (1 if trb[2] & (1 << 1) else 0)
    trb_str += '[ISP=%d]' % (1 if trb[2] & (1 << 2) else 0)
    trb_str += '[NS=%d]' % (1 if trb[2] & (1 << 3) else 0)
    trb_str += '[CH=%d]' % (1 if trb[2] & (1 << 4) else 0)
    trb_str += '[IOC=%d]' % (1 if trb[2] & (1 << 5) else 0)
    trb_str += '[IDT=%d]' % (1 if trb[2] & (1 << 6) else 0)
    trb_str += '[BEI=%d]' % (1 if trb[2] & (1 << 9) else 0)
    return trb_str

def parse_setup_trb(tx_trb):
    trb = unpack("<2B3HI2BH", tx_trb.data)
    trb_str = '[bmRequestType=%02x]' % trb[0]
    trb_str += '[bRequest=%02x]' % trb[1]
    trb_str += '[wValue=%04x]' % trb[2]
    trb_str += '[wIndex=%04x]' % trb[3]
    trb_str += '[wLength=%d]' % trb[4]
    trb_str += '[TRBTxLen=%d]' % (trb[5] & 0x1ffff)
    trb_str += '[IntrTarget=%d]' % (trb[5] >> 22)
    trb_str += '[C=%d]' % (trb[6] & 1)
    trb_str += '[IOC=%d]' % (1 if trb[6] & (1 << 5) else 0)
    trb_str += '[IDT=%d]' % (1 if trb[6] & (1 << 6) else 0)
    trb_str += '[TRT=%d]' % trb[8]
    return trb_str

def parse_data_trb(tx_trb):
    trb = unpack("<QI2H", tx_trb.data)
    trb_str = '[DataBufferPtr=%x]' % trb[0]
    trb_str += '[TRBTxLen=%d]' % (trb[1] & 0x1ffff)
    trb_str += '[TDSize=%d]' % ((trb[1] >> 17) & 0x1f)
    trb_str += '[IntrTarget=%d]' % (trb[1] >> 22)
    trb_str += '[C=%d]' % (trb[2] & 1)
    trb_str += '[ENT=%d]' % (1 if trb[2] & (1 << 1) else 0)
    trb_str += '[ISP=%d]' % (1 if trb[2] & (1 << 2) else 0)
    trb_str += '[NS=%d]' % (1 if trb[2] & (1 << 3) else 0)
    trb_str += '[CH=%d]' % (1 if trb[2] & (1 << 4) else 0)
    trb_str += '[IOC=%d]' % (1 if trb[2] & (1 << 5) else 0)
    trb_str += '[IDT=%d]' % (1 if trb[2] & (1 << 6) else 0)
    trb_str += '[BEI=%d]' % (1 if trb[2] & (1 << 9) else 0)
    trb_str += '[DIR=%d]' % (trb[3] & 1)
    return trb_str

def parse_status_trb(tx_trb):
    trb = unpack("<QI2H", tx_trb.data)
    trb_str = '[IntrTarget=%d]' % (trb[1] >> 22)
    trb_str += '[C=%d]' % (trb[2] & 1)
    trb_str += '[ENT=%d]' % (1 if trb[2] & (1 << 1) else 0)
    trb_str += '[CH=%d]' % (1 if trb[2] & (1 << 4) else 0)
    trb_str += '[IOC=%d]' % (1 if trb[2] & (1 << 5) else 0)
    trb_str += '[DIR=%d]' % (trb[3] & 1)
    return trb_str

def parse_isoch_trb(tx_trb):
    trb = unpack("<QI2H", tx_trb.data)
    trb_str = '[DataBufferPtr=%x]' % trb[0]
    trb_str += '[TRBTxLen=%d]' % (trb[1] & 0x1ffff)
    trb_str += '[TDSize=%d]' % ((trb[1] >> 17) & 0x1f)
    trb_str += '[IntrTarget=%d]' % (trb[1] >> 22)
    trb_str += '[C=%d]' % (trb[2] & 1)
    trb_str += '[ENT=%d]' % (1 if trb[2] & (1 << 1) else 0)
    trb_str += '[ISP=%d]' % (1 if trb[2] & (1 << 2) else 0)
    trb_str += '[NS=%d]' % (1 if trb[2] & (1 << 3) else 0)
    trb_str += '[CH=%d]' % (1 if trb[2] & (1 << 4) else 0)
    trb_str += '[IOC=%d]' % (1 if trb[2] & (1 << 5) else 0)
    trb_str += '[IDT=%d]' % (1 if trb[2] & (1 << 6) else 0)
    trb_str += '[TBC=%d]' % ((trb[2] >> 7) & 0X3)
    trb_str += '[BEI=%d]' % (1 if trb[2] & (1 << 9) else 0)
    trb_str += '[TLBPC=%d]' % (trb[3] & 0xf)
    trb_str += '[FrameID=%d]' % ((trb[3] << 1) >> 4)
    trb_str += '[SIA=%d]' % (1 if trb[3] & (1 << 15) else 0)
    return trb_str

def parse_noop_trb(tx_trb):
    trb = unpack("<QI2H", tx_trb.data)
    trb_str = '[IntrTarget=%d]' % (trb[1] >> 22)
    trb_str += '[C=%d]' % (trb[2] & 1)
    trb_str += '[ENT=%d]' % (1 if trb[2] & (1 << 1) else 0)
    trb_str += '[CH=%d]' % (1 if trb[2] & (1 << 4) else 0)
    trb_str += '[IOC=%d]' % (1 if trb[2] & (1 << 5) else 0)
    trb_str += '[DIR=%d]' % (trb[3] & 1)
    return trb_str

def parse_event_data_trb(tx_trb):
    trb = unpack("<QI2H", tx_trb.data)
    trb_str = '[EventDataPtr=%x]' % trb[0]
    trb_str += '[IntrTarget=%d]' % (trb[1] >> 22)
    trb_str += '[C=%d]' % (trb[2] & 1)
    trb_str += '[ENT=%d]' % (1 if trb[2] & (1 << 1) else 0)
    trb_str += '[CH=%d]' % (1 if trb[2] & (1 << 4) else 0)
    trb_str += '[IOC=%d]' % (1 if trb[2] & (1 << 5) else 0)
    trb_str += '[BEI=%d]' % (1 if trb[2] & (1 << 9) else 0)
    return trb_str

def get_tx_trb_data(tx_trb):
    tx_trb_type = (unpack("<3I2BH", tx_trb.data))[4] >> 2
    tx_trb_types = {
        1 : ["Normal TRB", parse_normal_trb(tx_trb)],
        2 : ["Setup Stage TRB", parse_setup_trb(tx_trb)],
        3 : ["Data Stage TRB", parse_data_trb(tx_trb)],
        4 : ["Status Stage TRB", parse_status_trb(tx_trb)],
        5 : ["Isoch TRB", parse_isoch_trb(tx_trb)],
        6 : ["Link TRB", ""],
        7 : ["Event Data TRB", parse_event_data_trb(tx_trb)],
        8 : ["No-Op TRB", parse_noop_trb(tx_trb)]}

    if tx_trb_type in tx_trb_types:
        return tx_trb_types[tx_trb_type]
    else:
        return ["Invalid Transfer Ring TRB Type", "Unknown"]


def xhci_tx_completion_handler(trace_seq, event):
    tx_trb_dma = long(event['dma'])
    tx_trb_va = long(event['va'])
    status = unpack("@H2B", event['status'].data)
    flags = unpack("@4B", event['flags'].data)
    trb_data = get_tx_trb_data(event['trb'])

    compl_status = get_compl_code_str(status[2]);
    tx_len = (status[1] << 16) | status[0]
    ed = flags[0] & 0x4
    event_type = flags[1] >> 2
    ep_id = flags[2];
    slot_id = flags[3];

    if event_type == 32:
        trace_seq.puts("Transfer Event\n")
    else:
        return
    trace_seq.puts("%-10s:\t%s\n" % ("TRB Type", trb_data[0]))
    trace_seq.puts("%-10s:\t%s\n" % ("Status", compl_status))
    trace_seq.puts("%-10s:\t@%x\n" % ("DMA addr", tx_trb_dma))
    trace_seq.puts("%-10s:\t@%x\n" % ("Virtual addr", tx_trb_va))
    trace_seq.puts("%-10s:\t%i\n" % ("EDTLA" if ed else "Transfer len", tx_len))
    trace_seq.puts("%-10s:\t%i\n" % ("EP ID", ep_id))
    trace_seq.puts("%-10s:\t%i\n" % ("Slot ID", slot_id))
    trace_seq.puts("%-10s:\t%s\n" % ("TRB Fields", trb_data[1]))


def register(pevent):
    pevent.register_event_handler('xhci-hcd', 'xhci_address_ctx',
                                  xhci_ctx_handler)
    pevent.register_event_handler('xhci-hcd', 'xhci_cmd_completion',
                                  xhci_cmd_handler)
    pevent.register_event_handler('xhci-hcd', 'xhci_tx_completion',
                                  xhci_tx_completion_handler)

