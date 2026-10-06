"""Unit tests for MailHog VIN/PIN parsing used during vehicle provisioning."""

from apishield.traffic.provision import decode_mail_body, parse_vin_pin


SAMPLE_BODY = (
    "Your vehicle information is <b>VIN: </font>"
    "<font face=3D'calibri' font color=3D'#0000ff'>9R4AW299W7T4E9DCT</font>"
    "</b> and <b>Pincode: <font face=3D'calibri' font color=3D'#0000ff'>"
    "5655</font></b>"
)


def test_parse_vin_pin_from_quoted_printable_html():
    vin, pin = parse_vin_pin(SAMPLE_BODY)
    assert vin == "9R4AW299W7T4E9DCT"
    assert pin == "5655"


def test_decode_mail_body_removes_soft_breaks():
    encoded = "Pinco=\r\nde: 1234"
    decoded = decode_mail_body(encoded)
    assert "Pincode" in decoded or "Pinco" in decoded
