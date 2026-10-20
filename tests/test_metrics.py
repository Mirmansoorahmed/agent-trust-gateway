from eval.metrics import bootstrap_ci, percentile, rate_record


def test_deterministic_rate_has_a_point_interval():
    assert bootstrap_ci(20, 20, seed=20261020) == [1.0, 1.0]
    assert bootstrap_ci(0, 20, seed=20261020) == [0.0, 0.0]


def test_partial_rate_interval_stays_inside_unit_interval():
    low, high = bootstrap_ci(10, 20, seed=20261020)
    assert 0 <= low <= 0.5 <= high <= 1


def test_percentiles_of_a_known_sample():
    assert percentile([1, 2, 3, 4], 0.5) == 2.5
    assert percentile([10, 20, 30], 0.95) > 20


def test_rate_record_shape():
    record = rate_record(20, 20, seed=1)
    assert record["rate"] == 1
    assert record["ci95"] == [1, 1]
