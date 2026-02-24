import csv
from io import StringIO

def format_csv(rows):
    """CSV formatlar."""
    output = StringIO()
    fieldnames = ["type", "value", "confidence", "source", "note"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return output.getvalue()