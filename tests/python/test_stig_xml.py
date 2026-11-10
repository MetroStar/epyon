"""STIG parsing preserves supported formats and rejects unsafe XML."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from defusedxml.common import DTDForbidden


PARSER_PATH = Path(__file__).resolve().parents[2] / "scripts/shell/parse-stig-cklb.py"
spec = importlib.util.spec_from_file_location("epyon_stig_xml_parser", PARSER_PATH)
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


def test_xccdf_parses_namespaced_controls(tmp_path):
    source = tmp_path / "controls.xml"
    source.write_text(
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">'
        "<title>Example STIG</title>"
        '<Group id="V-1"><Rule id="SV-1_rule" severity="high">'
        "<title>Example control</title>"
        "</Rule></Group></Benchmark>",
        encoding="utf-8",
    )
    result = parser.parse_stig(str(source))
    assert result["stig_name"] == "Example STIG"
    assert result["source_format"] == "xccdf"
    assert result["total_controls"] == 1
    assert result["controls"][0]["rule_id"] == "SV-1"


@pytest.mark.parametrize(
    ("suffix", "encoding"),
    [(".xml", "utf-8"), (".txt", "utf-8"), (".xml", "utf-16")],
)
def test_xml_dtds_are_rejected(tmp_path, suffix, encoding):
    source = tmp_path / f"controls{suffix}"
    xml = (
        f'<?xml version="1.0" encoding="{encoding}"?>'
        '<!DOCTYPE Benchmark [<!ENTITY payload "expanded">]>'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">'
        "<title>&payload;</title></Benchmark>"
    )
    source.write_bytes(xml.encode(encoding))
    with pytest.raises(DTDForbidden):
        parser.parse_stig(str(source))


def test_cklb_json_still_parses(tmp_path):
    source = tmp_path / "controls.cklb"
    source.write_text(
        json.dumps({"stigs": [{"stig_name": "Example STIG", "rules": [
            {"rule_id": "SV-1", "rule_title": "Example control"},
        ]}]}),
        encoding="utf-8",
    )
    result = parser.parse_stig(str(source))
    assert result["source_format"] == "cklb"
    assert result["total_controls"] == 1


def test_cli_reports_unsafe_xml_as_an_error(tmp_path):
    source = tmp_path / "unsafe.xml"
    source.write_text(
        '<!DOCTYPE Benchmark [<!ENTITY payload "expanded">]>'
        "<Benchmark>&payload;</Benchmark>",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(PARSER_PATH), str(source)],
        capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "[ERROR] Failed to parse STIG file:" in result.stderr
    assert result.stdout == ""
