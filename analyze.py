import argparse​
import dpkt​
import socket​
import os​
import sys​
import glob​
import gzip​
from functools import reduce​
from helper.csv_writer import write_to_csv, read_from_csv​
from helper.pcap_data import PcapData, DataInfo​
from helper.create_plots import plot_all​
from helper.util import check_directory, print_line,
open_compressed_file, colorize​
from helper import PCAP1, PCAP2, PLOT_PATH, CSV_PATH, PLOT_TYPES​
from helper import BUFFER_FILE_EXTENSION, FLOW_FILE_EXTENSION​
from helper import COMPRESSION_METHODS, COMPRESSION_EXTENSIONS​
​
def main():​
parser = argparse.ArgumentParser()​
parser.add_argument('-d', '--directory', dest='directory',​
default='.', help='Path to the working
directory (default: .)')​
parser.add_argument('-s', '--source', dest='source',​
choices=['pcap', 'csv'],​
default='pcap', help='Create plots from csv or
pcap')​
parser.add_argument('-o', '--output', dest='output',​
choices=['pdf+csv', 'pdf', 'csv'],​
default='pdf+csv', help='Output Format
(default: pdf+csv)')​
parser.add_argument('-t', '--delta-t', dest='delta_t',​
default='0.2', help='Interval in seconds for
computing average throughput (default: 0.2)')​
parser.add_argument('-r', '--recursive', dest='recursive',
action='store_true',​
help='Process all sub-directories
recursively.')​
parser.add_argument('-n', '--new', dest='new',
action='store_true',​
help='Only process new (unprocessed)
directories.')​
parser.add_argument('--hide-total', dest='hide_total',
action='store_true',​
help='Hide total values in plots for sending
rate, throughput, ...')​
parser.add_argument('-a', '--add-plot', action='append',
choices=PLOT_TYPES, dest='added_plots',​
help='Add a plot to the final PDF output. Thisis overwritten by the -i option if both are given.')​
parser.add_argument('-i', '--ignore-plot', action='append',
choices=PLOT_TYPES,​
dest='ignored_plots',​
help='Remove a plot from the PDF output. This
overwrites the -a option.')​
parser.add_argument('-c', '--compression', dest='compression',​
choices=COMPRESSION_METHODS,
default=COMPRESSION_METHODS[1],​
help='Compression method of the output files.
Default: {}'.format(COMPRESSION_METHODS[1]))​
parser.add_argument('--all-plots', dest='all_plots',
action='store_true',​
help='Additionally store each plot in an
individual PDF file.')​
args = parser.parse_args()​
directory = args.directory​
paths = []​
plots = PLOT_TYPES​
​
if args.added_plots is not None:​
plots = args.added_plots​
if args.ignored_plots is not None:​
plots = [p for p in PLOT_TYPES if p not in args.ignored_plots]​
​
if args.recursive:​
for subdirs, _, _ in os.walk(directory):​
if check_directory(subdirs, only_new=args.new):​
paths.append(subdirs)​
else:​
if check_directory(directory, only_new=args.new):​
paths = [directory]​
​
print('Found {} valid sub directories.'.format(len(paths)))​
paths = sorted(paths)​
​
for i, directory in enumerate(paths):​
print('{}/{} Processing {}'.format(i + 1, len(paths),
directory))​
​
if args.source == 'pcap':​
# Assumes parse_pcap is defined elsewhere and returns
PcapData or equivalent​
pcap_data = parse_pcap(path=directory,
delta_t=float(args.delta_t))​
if 'csv' in args.output:​
string = 'Writing to CSV'​
if args.compression != COMPRESSION_METHODS[0]:​string += ' and compressing with
{}'.format(args.compression)​
print(string)​
write_to_csv(directory, pcap_data,
compression=args.compression)​
else:​
pcap_data = read_from_csv(directory)​
if pcap_data == -1:​
continue​
​
if 'pdf' in args.output:​
if args.all_plots:​
print('Creating {} plots'.format(len(plots) + 1))​
else:​
print('Creating Complete plot')​
plot_all(directory, pcap_data, plot_only=plots,
hide_total=args.hide_total,​
all_plots=args.all_plots)​
​
# --- Fix reduce usage in parse_pcap (example snippet) ---​
def parse_tcp_timestamp(opt):​
# Python 3 dpkt bytes don't need ord()​
ts_val = reduce(lambda x, r: (x << 8) + r, opt[:4])​
ts_ecr = reduce(lambda x, r: (x << 8) + r, opt[4:])​
return ts_val, ts_ecr​