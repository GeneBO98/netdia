from netdia.models import WebsiteFinding
from netdia.opnsense import extract_candidates


def test_extract_candidates_from_nested_payload() -> None:
    payload = {
        "rows": [
            {"domain": "home.example.com", "upstream": "192.168.1.10:443"},
            {"domain": "grafana.example.com", "upstreams": ["192.168.1.50:3000"]},
        ]
    }
    assert extract_candidates(payload) == [
        ("home.example.com", "192.168.1.10:443"),
        ("grafana.example.com", "192.168.1.50:3000"),
    ]


def test_website_finding_upstream_field() -> None:
    finding = WebsiteFinding(hostname="lab.example.com", scheme="https", source="opnsense_caddy", upstream_target="192.168.1.10:443")
    assert finding.upstream_target == "192.168.1.10:443"
