#!/usr/bin/python

import pefile
import sys
import argparse
import os
import pprint
import networkx
import re
from networkx.drawing.nx_agraph import write_dot
import collections
from networkx.algorithms import bipartite

args = argparse.ArgumentParser("Visualize shared sections between a directory of malware samples")
args.add_argument("target_path",help="directory with malware samples")
args.add_argument("output_file",help="file to write DOT file to")
args.add_argument("malware_projection",help="file to write DOT file to")
args.add_argument("section_projection",help="file to write DOT file to")
args = args.parse_args()
network = networkx.Graph()

# search the target directory for valid Windows PE executable files
for root,dirs,files in os.walk(args.target_path):
    for path in files:
        # try opening the file with pefile to see if it's really a PE file
        try:
            pe = pefile.PE(os.path.join(root,path))
        except pefile.PEFormatError:
            continue

        sections = []
        for s in pe.sections:
            sections.append(s.Name)
        if len(sections):
            # add the nodes and edges for the bipartite network
            network.add_node(path,label=path[:32],color='black',penwidth=5,bipartite=0)
            for section in sections:
                network.add_node(section,label=section,color='blue',penwidth=10,bipartite=1)
                network.add_edge(section,path,penwidth=2)
        if sections:
            print("Extracted sections from:",path)
            pprint.pprint(sections)

# write the dot file to disk
write_dot(network, args.output_file)
malware = set(n for n,d in network.nodes(data=True) if d['bipartite']==0)
section = set(network)-malware

# use NetworkX's bipartite network projection function to produce the malware
# and section projections
malware_network = bipartite.projected_graph(network, malware)
section_network = bipartite.projected_graph(network, section)

# write the projected networks to disk as specified by the user
write_dot(malware_network,args.malware_projection)
write_dot(section_network,args.section_projection)