#!/usr/bin/env python
# -*- coding: utf-8 -*-
import csv
import sys
import pathlib

if len(sys.argv) != 2:
   print("Usage: python parse_result.py <filename>")
   exit(1)



signatures_dict = {}


with open(sys.argv[1], newline='', encoding='utf-8') as csvfile:
   reader = csv.DictReader(csvfile, delimiter=";")
   fields = reader.fieldnames
   for row in reader:
      sha256 = row['Lookup Hash']
      rating = row['Rating']
      signature = row['Matching Rule']

      if signature not in signatures_dict:
         signatures_dict[signature] = {
            "stats": {},
            "csv_path": pathlib.Path(sys.argv[1]).with_name(f"{pathlib.Path(sys.argv[1]).stem}_{signature}.csv"),
            "csv": csv.DictWriter(pathlib.Path(sys.argv[1]).with_name(f"{pathlib.Path(sys.argv[1]).stem}_{signature}.csv").open("w", newline=''), fieldnames=fields, delimiter=";")
         }
         signatures_dict[signature]["csv"].writeheader()
      try:
         row.pop(None)
      except KeyError:
         pass
      signatures_dict[signature]["csv"].writerow(row)
      try:
         signatures_dict[signature]["stats"][rating] += 1
      except:
         signatures_dict[signature]["stats"][rating] = 1

for signature, data in signatures_dict.items():
   print("*"*100)
   print("# VT retrohunt summary for", signature)
   print("|Rating|Hits|Hit percentage|")
   print("|---|---|---|")

   total_hits = sum(data["stats"].values())
   for key, val in data["stats"].items():
        print(f"|{key}|{val}|{int((100*val)/total_hits)}|")
   print(f"|Total|{total_hits}|100|")

   print(f"CSV file: {data['csv_path']}")
