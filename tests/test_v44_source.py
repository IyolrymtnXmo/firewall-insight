from conftest import app_source
MAIN = app_source()


def test_traffic_ui_accepts_domains_and_service_names():
    """The Traffic Path form must say that source/destination take an IP OR an
    FQDN, and that the service field takes a port, a service name, or a Check
    Point service object.

    Asserted by meaning rather than by one exact placeholder string: v4.13
    moved that information from four bare placeholders into visible field
    labels, because a row of unlabelled inputs gave no clue which box was
    which until you clicked into it.
    """
    assert '<label class="field"><span>Source</span>' in MAIN
    assert '<label class="field"><span>Destination</span>' in MAIN
    assert "<span>Port / Service</span>" in MAIN
    assert MAIN.count('placeholder="IP or FQDN"') == 2
    assert 'placeholder="443, https, or a service object"' in MAIN
    assert "service:port.value.trim()" in MAIN


def test_traffic_ui_states_that_no_packet_is_sent():
    assert "No packet is sent" in MAIN


def test_ui_prefers_hierarchical_display_rule():
    assert "r.display_rule||r.rule" in MAIN
