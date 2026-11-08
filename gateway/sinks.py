"""Sinks: places events get written to. Each sink has write(event_dict).

M1: a JSON Lines file (one event per line). The live dashboard feed will be another sink.
"""
import json
import os


class JsonlSink:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._file = open(path, "w", encoding="utf-8")  # fresh file per gateway run

    def write(self, event):
        self._file.write(json.dumps(event, ensure_ascii=False) + "\n")
        self._file.flush()

    def close(self):
        self._file.close()
