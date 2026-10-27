"""Convert every Sigma rule into SIEM queries with pySigma.

Output (one file per rule and per SIEM):

    build/queries/splunk/<rule>.spl         Splunk SPL
    build/queries/elastic/<rule>.lucene     Elastic / Kibana (Lucene, ECS fields)
    build/queries/sentinel/<rule>.kql       Microsoft Sentinel / Defender XDR (KQL)

The processing pipeline (field mapping) is chosen from the rule's log source.
For example, Windows rules use the Sysmon + Splunk Windows pipelines for Splunk
and the ECS pipeline for Elastic.

Usage:
    python -m scripts.convert_rules
    python -m scripts.convert_rules --output build/queries
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.plugins import InstalledSigmaPlugins

ROOT = Path(__file__).resolve().parent.parent


class UnsupportedLogSource(Exception):
    """The SIEM has no mapping for this log source in this project."""


@dataclass(frozen=True)
class Target:
    name: str  # folder name
    backend: str  # pySigma backend id (see `sigma list targets`)
    extension: str
    # product -> list of pipeline ids. "*" is used when the product is not listed.
    # If neither the product nor "*" is listed, the rule is skipped for this SIEM.
    pipelines: dict[str, list[str]]


TARGETS = [
    Target("splunk", "splunk", "spl", {"windows": ["sysmon", "splunk_windows"], "*": []}),
    Target("elastic", "lucene", "lucene", {"windows": ["ecs_windows"], "*": []}),
    # Defender XDR tables (DeviceProcessEvents...) cover Windows and Linux endpoints.
    # AWS CloudTrail needs a custom table mapping (AWSCloudTrail): see the roadmap.
    Target("sentinel", "kusto", "kql", {"windows": ["microsoft_xdr"], "linux": ["microsoft_xdr"]}),
]


def convert_rule(path: Path, target: Target, plugins: InstalledSigmaPlugins) -> list[str]:
    # Parse the rule again for every target: pipelines change the rule in place.
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    product = collection.rules[0].logsource.product or "*"
    pipeline_ids = target.pipelines.get(product, target.pipelines.get("*"))
    if pipeline_ids is None:
        raise UnsupportedLogSource(f"no field mapping for product '{product}' yet")
    pipeline = plugins.get_pipeline_resolver().resolve(pipeline_ids) if pipeline_ids else None
    backend = plugins.backends[target.backend](processing_pipeline=pipeline)
    return [str(query) for query in backend.convert(collection)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--rules", type=Path, default=ROOT / "detections")
    parser.add_argument("--output", type=Path, default=ROOT / "build" / "queries")
    args = parser.parse_args(argv)

    plugins = InstalledSigmaPlugins.autodiscover()
    rules = sorted(args.rules.rglob("*.yml"))
    errors = 0
    skipped: list[str] = []

    print(f"{'rule':<52} " + " ".join(f"{t.name:<9}" for t in TARGETS))
    for path in rules:
        cells = []
        for target in TARGETS:
            try:
                queries = convert_rule(path, target, plugins)
            except (SigmaError, UnsupportedLogSource) as exc:
                # Some log sources do not exist in some SIEM schemas (for example the
                # Windows Security channel in Defender XDR). That is expected.
                skipped.append(f"{path.stem} -> {target.name}: {str(exc).splitlines()[0]}")
                cells.append("skipped")
                continue
            except Exception as exc:  # noqa: BLE001 - report and keep going
                errors += 1
                skipped.append(f"{path.stem} -> {target.name}: ERROR {exc}")
                cells.append("ERROR")
                continue
            out_file = args.output / target.name / f"{path.stem}.{target.extension}"
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text("\n\n".join(queries) + "\n", encoding="utf-8")
            cells.append("ok")
        print(f"{path.stem:<52} " + " ".join(f"{c:<9}" for c in cells))

    if skipped:
        print("\nNot converted:")
        for line in skipped:
            print(f"  - {line}")
    print(f"\nQueries written to {args.output}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
