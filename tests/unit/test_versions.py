"""Version-range evaluation: we must not assume 'returned by OSV' means 'affected'."""

from cybersentinel.ingestion.versions import AFFECTED, NOT_AFFECTED, UNVERIFIED, evaluate


def affected_entry(ecosystem, name, events, rtype="ECOSYSTEM", versions=None):
    return [
        {
            "package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{"type": rtype, "events": events}],
            "versions": versions or [],
        }
    ]


def test_pypi_version_inside_range_is_affected_with_fixed_version():
    aff = affected_entry("PyPI", "django", [{"introduced": "4.2"}, {"fixed": "4.2.28"}])
    result = evaluate("PyPI", "Django", "4.2.0", aff)
    assert result.status == AFFECTED
    assert result.fixed_version == "4.2.28"


def test_pypi_version_after_fix_is_not_affected():
    aff = affected_entry("PyPI", "django", [{"introduced": "4.2"}, {"fixed": "4.2.1"}])
    assert evaluate("PyPI", "Django", "4.2.5", aff).status == NOT_AFFECTED


def test_pep440_ordering_is_used_not_string_ordering():
    # As strings "4.2.10" < "4.2.9"; as versions it is the opposite.
    aff = affected_entry("PyPI", "django", [{"introduced": "0"}, {"fixed": "4.2.10"}])
    assert evaluate("PyPI", "Django", "4.2.9", aff).status == AFFECTED


def test_npm_semver_prerelease_sorts_before_release():
    aff = affected_entry(
        "npm", "express", [{"introduced": "5.0.0-beta.1"}, {"fixed": "5.0.0"}], rtype="SEMVER"
    )
    assert evaluate("npm", "express", "5.0.0-beta.3", aff).status == AFFECTED
    assert evaluate("npm", "express", "5.0.0", aff).status == NOT_AFFECTED


def test_last_affected_is_inclusive():
    aff = affected_entry("Maven", "org.example:lib", [{"introduced": "1.0"}, {"last_affected": "1.4"}])
    assert evaluate("Maven", "org.example:lib", "1.4", aff).status == AFFECTED
    assert evaluate("Maven", "org.example:lib", "1.5", aff).status == NOT_AFFECTED


def test_introduced_without_fix_means_still_affected():
    aff = affected_entry("PyPI", "flask", [{"introduced": "2.0"}])
    result = evaluate("PyPI", "Flask", "2.3.0", aff)
    assert result.status == AFFECTED
    assert result.fixed_version is None


def test_explicit_version_list_counts_as_affected():
    aff = affected_entry("PyPI", "requests", [], versions=["2.28.0"])
    assert evaluate("PyPI", "requests", "2.28.0", aff).status == AFFECTED


def test_git_only_ranges_are_unverified():
    aff = affected_entry("PyPI", "jinja2", [{"introduced": "abc123"}, {"fixed": "def456"}], rtype="GIT")
    assert evaluate("PyPI", "Jinja2", "3.1.2", aff).status == UNVERIFIED


def test_other_package_in_advisory_is_ignored():
    aff = affected_entry("PyPI", "something-else", [{"introduced": "0"}, {"fixed": "9.9"}])
    assert evaluate("PyPI", "Django", "4.2.0", aff).status == UNVERIFIED


def test_maven_non_numeric_version_is_unverified_not_guessed():
    aff = affected_entry("Maven", "org.example:lib", [{"introduced": "1.0"}, {"fixed": "2.0"}])
    assert evaluate("Maven", "org.example:lib", "1.5-SNAPSHOT", aff).status == UNVERIFIED


def test_pypi_names_are_normalised():
    aff = affected_entry("PyPI", "zope_interface", [{"introduced": "0"}, {"fixed": "5.0"}])
    assert evaluate("PyPI", "Zope.Interface", "4.0", aff).status == AFFECTED
