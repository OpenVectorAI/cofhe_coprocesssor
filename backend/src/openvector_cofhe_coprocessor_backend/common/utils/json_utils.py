from __future__ import annotations

import json
from jsonschema import validate

def read_json_file(file_path):
    with open(file_path, "r") as file:
        return json.load(file)
    
def read_json_config(file_path, schema):
    config = read_json_file(file_path)
    validate(config, schema)
    return config