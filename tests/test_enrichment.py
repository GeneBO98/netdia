from netdia.enrichment import extract_title, extract_tls_names_from_cert, should_probe_web


def test_extract_title() -> None:
    html = "<html><head><title> Home Lab </title></head></html>"
    assert extract_title(html) == "Home Lab"


def test_extract_tls_names_from_cert() -> None:
    cert = {
        "subjectAltName": [("DNS", "lab.example.com"), ("DNS", "grafana.example.com")],
        "subject": ((("commonName", "lab.example.com"),),),
    }
    assert extract_tls_names_from_cert(cert) == ["grafana.example.com", "lab.example.com"]


def test_should_probe_web() -> None:
    assert should_probe_web("http", 8080) is True
    assert should_probe_web("postgresql", 5432) is False
