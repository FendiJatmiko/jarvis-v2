# test_wp_match.py
import wp_match

def test_le_constraint():
    assert wp_match.version_satisfies("6.0", "<=6.8") is True
    assert wp_match.version_satisfies("6.8", "<=6.8") is True
    assert wp_match.version_satisfies("6.9", "<=6.8") is False

def test_range_constraint():
    assert wp_match.version_satisfies("7.0.4", ">=7.0.0,<=7.0.4") is True
    assert wp_match.version_satisfies("7.0.5", ">=7.0.0,<=7.0.4") is False
    assert wp_match.version_satisfies("6.9.9", ">=7.0.0,<=7.0.4") is False

def test_uneven_length_versions():
    assert wp_match.version_satisfies("6", "<=6.8") is True
    assert wp_match.version_satisfies("6.8.1", "<=6.8") is False

def test_exact_default_operator():
    assert wp_match.version_satisfies("6.8", "6.8") is True
    assert wp_match.version_satisfies("6.7", "6.8") is False
