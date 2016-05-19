#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Project : TCPStats
# Author  : Jakub Šoustar <jakub.soustar@gmail.com> <xsoust02@stud.fit.vutbr.cz>
#

from __future__ import print_function

from collections import defaultdict
from scapy.all import *

import argparse
import errno
import json
import os

summary = {
	"options": [],
	"packets": 0,
	"bytes": 0,
	"start": None,
	"end": None,
	"parties": defaultdict(lambda: {
		"options": [],
		"packets": 0,
		"bytes": 0,
		"ip": None
	})
}

throughput_stat = defaultdict(lambda: {
	"time_offset": None,
	"buffer": [],
	"values": [],
	"last": None
})

sequence_stat = defaultdict(lambda: {
	"time_offset": None,
	"seq_offset": None,
	"values": []
})

window_stat = defaultdict(lambda: {
	"time_offset": None,
	"scale": None,
	"values": []
})

rtt_stat = defaultdict(lambda: {
	"seq_offset": None,
	"buffer": [],
	"values": []
})

receiver = None
sender = None

# Replace receiver and sender IPs with "receiver" and "sender" strings
def replace_roles(stat):
	if receiver in stat:
		stat["receiver"] = stat.pop(receiver)

	if sender in stat:
		stat["sender"] = stat.pop(sender)

	return stat

# Convert a time stat (x-value or y-value is time in seconds) into
# dictionary that can be dumped into resulting JSON
def get_time_stat(stat, x_ms=False, y_ms=False):
	x_mult = 1000 if x_ms else 1
	y_mult = 1000 if y_ms else 1

	# Collect all values into [x-value, y-value] pairs.
	# Multiply time by 1000 to get time in milliseconds.
	json_stat = {
		src_ip: {
			"ip": src_ip,
			"data": [
				[round(x_val * x_mult, 6), round(y_val * y_mult, 6)]
				for x_val, y_val
				in stat[src_ip]["values"]
			]
		}
		for src_ip
		in stat
	}

	return replace_roles(json_stat)

# Collect data about throughput
def process_throughput_stat(packet):
	ip_layer = IPv6 if IPv6 in packet else IP
	stat = throughput_stat[packet[ip_layer].src]

	# Capture first packet's time to calculate relative arrival times
	if not stat["time_offset"]:
		stat["time_offset"] = packet.time

	# Get relative arrival time
	time = packet.time - stat["time_offset"]
	# Get size of packet's payload
	size = len(packet[TCP].payload)

	stat["buffer"].append((time, size))

	# Delete oldest values from the buffer so that it contains
	# only values for 1 second
	while stat["buffer"] and time - stat["buffer"][0][0] > 1:
		del stat["buffer"][0]

	# Measure throughput (in bytes per second) at max every 0.1 second
	if not stat["last"] or time - stat["last"] > 0.1:
		size = reduce(lambda bs, (_, s): bs + s, stat["buffer"], 0)
		stat["last"] = time

		stat["values"].append((time, size))

# Collect data about sequence numbers
def process_sequence_stat(packet):
	ip_layer = IPv6 if IPv6 in packet else IP
	stat = sequence_stat[packet[ip_layer].src]

	# Capture first packet's time to calculate relative arrival times
	if not stat["time_offset"]:
		stat["time_offset"] = packet.time

	# Capture first packet's seq to calculate relative seq numbers
	if not stat["seq_offset"]:
		stat["seq_offset"] = packet[TCP].seq

	time_offset = stat["time_offset"]
	seq_offset = stat["seq_offset"]

	# Get relative arrival time
	time = packet.time - time_offset
	# Get relative seq number
	seq = packet[TCP].seq - seq_offset

	stat["values"].append((time, seq))

# Collect data about window size
def process_window_stat(packet):
	ip_layer = IPv6 if IPv6 in packet else IP
	src_stat = window_stat[packet[ip_layer].src]
	dst_stat = window_stat[packet[ip_layer].dst]

	# Capture first packet's time to calculate relative arrival times
	if not src_stat["time_offset"]:
		src_stat["time_offset"] = packet.time

	# Capture WScale option
	if not src_stat["scale"]:
		for option, value in packet[TCP].options:
			if option == "WScale":
				src_stat["scale"] = value
				return

	# Use the scale only AFTER both sides sent the WScale option
	scale = src_stat["scale"] if src_stat["scale"] and dst_stat["scale"] else 0
	time_offset = src_stat["time_offset"]

	# Get relative arrival time
	time = packet.time - time_offset
	# Shift window size by WScale
	size = packet[TCP].window << scale

	src_stat["values"].append((time, size))

# Collect data about round trip times
def process_rtt_stat(packet):
	ip_layer = IPv6 if IPv6 in packet else IP
	src_stat = rtt_stat[packet[ip_layer].src]
	dst_stat = rtt_stat[packet[ip_layer].dst]
	flags = packet.sprintf("%TCP.flags%")

	# Capture first packet's seq to calculate relative seq numbers
	if not src_stat["seq_offset"]:
		src_stat["seq_offset"] = packet[TCP].seq

	if packet[TCP].payload or "S" in flags or "F" in flags:
		src_stat["buffer"].append((packet[TCP].seq, packet.time))
		src_stat["buffer"].sort(key=lambda i: i[0])

	if dst_stat and "A" in flags:
		dst_buffer = dst_stat["buffer"]
		val_buffer = []

		# Collect all packet ACK'ed by this one
		while dst_buffer and dst_buffer[0][0] < packet[TCP].ack:
			val_buffer.append(dst_buffer.pop(0))

		if val_buffer:
			# Get the time difference between ACK packet and last packet it ACK'ed
			time = packet.time - val_buffer[-1][1]

			for seq, _ in val_buffer:
				# Get relative seq number
				dst_stat["values"].append((seq - dst_stat["seq_offset"], time))

# Collect summary data
def process_summary(packet):
	ip_layer = IPv6 if IPv6 in packet else IP
	src_stat = summary["parties"][packet[ip_layer].src]
	packet_size = len(packet)

	# Get sender's IP address
	if not src_stat["ip"]:
		src_stat["ip"] = packet[ip_layer].src

	# Sender summary
	for option, _ in packet[TCP].options:
		if option not in src_stat["options"]:
			src_stat["options"].append(option)

		if option not in summary["options"]:
			summary["options"].append(option)

	src_stat["bytes"] += packet_size
	src_stat["packets"] += 1

	# Total summary
	if not summary["start"]:
		summary["start"] = packet.time

	summary["bytes"] += packet_size
	summary["end"] = packet.time
	summary["packets"] += 1

def process_packet(packet):
	global receiver
	global sender

	ip_layer = IPv6 if IPv6 in packet else IP if IP in packet else None

	if not ip_layer:
		return

	if not receiver and not sender:
		receiver = packet[ip_layer].dst
		sender = packet[ip_layer].src

	process_summary(packet)
	process_throughput_stat(packet)
	process_sequence_stat(packet)
	process_window_stat(packet)
	process_rtt_stat(packet)

def main():
	arg_parser = argparse.ArgumentParser(description="TCPStats")
	arg_parser.add_argument("file", nargs=1, type=argparse.FileType("rb"), help="PCAP file containing a single stream to analyze")

	args = arg_parser.parse_args()
	file = args.file[0]

	sniff(offline=file.name, filter="tcp", prn=process_packet, store=0)

	replace_roles(summary["parties"])
	summary["start"] *= 1000
	summary["end"] *= 1000

	tcp_stats = {
		"summary": summary,
		"throughput": get_time_stat(throughput_stat),
		"sequence": get_time_stat(sequence_stat),
		"window": get_time_stat(window_stat),
		"rtt": get_time_stat(rtt_stat, y_ms=True)
	}

	dump = json.dumps(tcp_stats, separators=(",", ":"))
	path = "log/dump.js"

	# Source: http://stackoverflow.com/a/23794010
	try:
		os.makedirs(os.path.dirname(path))
	except OSError as e:
		if e.errno == errno.EEXIST and os.path.isdir(os.path.dirname(path)):
			pass
		else:
			raise

	print("var TCPStats = ", dump, ";", sep="", file=open(path, "w+"))

if __name__ == "__main__":
	main()
