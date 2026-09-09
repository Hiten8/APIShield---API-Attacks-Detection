from apishield.ingestion.normalizer import RequestNormalizer

def test_numeric_id_is_normalized():
    normalizer = RequestNormalizer()
    result = normalizer.normalize_path(
        "/api/users/123"
    )

    assert result == "/api/users/{id}"


def test_multiple_ids_are_normalized():
    normalizer = RequestNormalizer()
    result = normalizer.normalize_path(
        "/api/users/123/orders/456"
    )

    assert result == "/api/users/{id}/orders/{id}"


def test_uuid_is_normalized():
    normalizer = RequestNormalizer()
    result = normalizer.normalize_path(
        "/api/users/550e8400-e29b-41d4-a716-446655440000"
    )

    assert result == "/api/users/{id}"


def test_normal_path_is_unchanged():
    normalizer = RequestNormalizer()

    result = normalizer.normalize_path(
        "/api/users/profile"
    )

    assert result == "/api/users/profile"