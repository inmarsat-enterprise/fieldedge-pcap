#!/bin/bash
pdoc --html fieldedge_pcap --output-dir docs --force
mv ./docs/fieldedge_pcap/* ./docs
rm -r ./docs/fieldedge_pcap
