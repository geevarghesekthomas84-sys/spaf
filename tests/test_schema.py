import json

from spaf.service import schema as schema_mod
from spaf.service.models import Finding


def test_build_schemas_covers_public_models():
    schemas = schema_mod.build_schemas()
    for name in ["Finding", "ScanResult", "AgentResult", "ScopeState", "ToolStatus"]:
        assert name in schemas
        assert schemas[name]["type"] == "object"
        assert "properties" in schemas[name]


def test_finding_schema_has_core_fields():
    props = schema_mod.build_schemas()["Finding"]["properties"]
    for field in ["target", "vuln_type", "severity", "recommendation", "scan_type"]:
        assert field in props


def test_combined_schema_is_valid_json_and_has_defs():
    doc = schema_mod.combined_schema()
    # round-trips as JSON
    json.loads(json.dumps(doc))
    assert "$defs" in doc and "Finding" in doc["$defs"]
    assert doc["$schema"].startswith("https://json-schema.org/")


def test_write_schemas(tmp_path):
    paths = schema_mod.write_schemas(str(tmp_path))
    assert any(p.endswith("spaf.schema.json") for p in paths)
    # each written file is valid JSON
    for p in paths:
        json.load(open(p))


def test_schema_matches_live_model():
    # A real Finding validates against the properties the schema advertises.
    f = Finding.from_dict({"target": "x", "vuln_type": "t", "severity": "High"})
    dumped = f.model_dump()
    for key in schema_mod.build_schemas()["Finding"]["properties"]:
        assert key in dumped
