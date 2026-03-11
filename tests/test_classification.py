from netdia.classification import classify_host, classify_service, icon_for_category


def test_host_classification_prefers_firewall_signals() -> None:
    category = classify_host(["http", "dnsmasq"], [53, 80, 443], "OPNsense")
    assert category == "firewall"


def test_service_classification_marks_http_as_reverse_proxy() -> None:
    category = classify_service("http", 8080, "Caddy")
    assert category == "reverse_proxy"
    assert icon_for_category(category) == "route"
