import json

input_file = "storage/events.jsonl"
output_file = "storage/clean.jsonl"

with open(input_file, "r") as f, open(output_file, "w") as out:
    for line in f:
        data = json.loads(line)

        data.pop("is_vpn", None)
        data.pop("is_cloud", None)

        out.write(json.dumps(data) + "\n")