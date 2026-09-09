from apishield.conformance.path_matcher import OpenAPIPathMatcher


def test_exact_path_takes_precedence_over_parameterized_path():
    matcher = OpenAPIPathMatcher()

    paths = {
        "/workshop/api/shop/orders/{order_id}": {},
        "/workshop/api/shop/orders/all": {},
    }

    result = matcher.find_match(
        "/workshop/api/shop/orders/all",
        paths,
    )

    assert result is not None

    template, parameters = result

    assert template == "/workshop/api/shop/orders/all"
    assert parameters == {}