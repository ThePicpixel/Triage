import csv
import datetime
from pathlib import Path
from typing import Optional

from triage.graph import graph


def run_batch(samples_dir: str, output_dir: str = "reports") -> str:
    """Run the triage graph over every file in samples_dir.
    Writes a CSV to output_dir/batch-<timestamp>.csv and returns its path."""
    samples = [p for p in Path(samples_dir).iterdir() if p.is_file()]
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_path = Path(output_dir) / f"batch-{timestamp}.csv"
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    fieldnames = ["filename", "sha256", "classification", "confidence", "report_path", "error"]

    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for sample in sorted(samples):
            row: dict = {"filename": sample.name, "sha256": "", "classification": "",
                         "confidence": "", "report_path": "", "error": ""}
            try:
                result = graph.invoke({"file_path": str(sample), "findings": []})
                verdict = result.get("verdict", {})
                row["sha256"] = result.get("sha256", "")
                row["classification"] = verdict.get("classification", "")
                row["confidence"] = verdict.get("confidence", "")
                row["report_path"] = result.get("report_path", "")
            except Exception as exc:
                row["classification"] = "error"
                row["error"] = str(exc)
            writer.writerow(row)

    return str(csv_path)


if __name__ == "__main__":
    import sys
    samples_dir = sys.argv[1] if len(sys.argv) > 1 else "samples"
    out = run_batch(samples_dir)
    print(f"Batch complete: {out}")
