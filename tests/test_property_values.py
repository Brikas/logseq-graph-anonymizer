import pytest

from anonymize_graph import (
    PROPERTY_RE,
    anonymize_page_body,
    anonymize_page_ref,
    anonymize_property_value,
    check_schema_version,
    fake_property_key,
    load_property_policy,
    scrub_config_edn,
)

SALT = b"test-salt"
POLICY = load_property_policy()


def anon(line: str) -> str:
    return anonymize_page_body(SALT, line, keep_code=False, policy=POLICY)


def key_and_value(line: str) -> tuple:
    _, key, value = PROPERTY_RE.match(line).groups()
    return key, value


def test_src_key_link_label_and_url_are_faked():
    out = anon("\t\t  src:: [How long can you use betamethasone cream for?](https://www.drugs.com/medical-answers/x)")
    key, value = key_and_value(out)
    assert key != "src"
    assert "betamethasone" not in value and "drugs.com" not in value
    assert ".example/" in value


def test_capitalised_key_maps_to_the_same_fake_key():
    assert key_and_value(anon("Src:: x"))[0] == key_and_value(anon("src:: y"))[0]
    assert "Isabele" not in anon("  src:: ((6713b765-5bb4-4e6a-b28b-3c42e4af93e4)), Isabele")


def test_blockref_value_survives_under_a_faked_key():
    out = anon("  src:: ((6713b765-5bb4-4e6a-b28b-3c42e4af93e4))")
    assert out.endswith(":: ((6713b765-5bb4-4e6a-b28b-3c42e4af93e4))")


def test_custom_key_and_page_refs_are_faked():
    key, value = key_and_value(anon("skills:: [[Web-scraping]], [[Python]]"))
    assert key != "skills"
    assert value.startswith("[[") and "Python" not in value


def test_kept_properties_stay_byte_for_byte():
    for line in [
        "  collapsed:: true",
        "  id:: 64f1a1a0-2222-4a22-9a22-000000000001",
        "  logseq.order-list-type:: number",
        "  background-color:: purple",
        "query-properties:: [:page :block]",
        "  heading:: 2",
        "icon:: 🚀",
        "tine.view:: table",
        "tine.col-widths:: 0=140;1=180",
        "priority:: high",
    ]:
        assert anon(line) == line


def test_values_outside_the_allowed_list_are_faked():
    assert anon("priority:: Acme deal").startswith("priority:: ")
    assert "Acme" not in anon("priority:: Acme deal")
    assert "Acme" not in anon("background-color:: Acme")


def test_safe_literals_stay_under_a_faked_key():
    for line in ["example-property:: 15", "col-w-2:: 323px", "last-updated:: 2026-09-24",
                 "card-next-schedule:: 2023-05-20T08:28:09.505Z"]:
        assert key_and_value(anon(line))[1] == key_and_value(line)[1]


def test_bulleted_property_block_is_anonymized_as_a_property():
    out = anon("- companies:: Acme")
    assert out.startswith("- ") and "::" in out and "Acme" not in out and "companies" not in out


def test_tine_fields_names_and_enum_options_match_the_rows():
    fields = anon("tine.fields:: state=state;topic=enum:infra,ui;points=number")
    row_topic = anon("topic:: infra")
    row_points = anon("points:: 3")
    fake_topic, fake_infra = key_and_value(row_topic)
    fake_points = key_and_value(row_points)[0]
    assert "infra" not in fields and "topic" not in fields
    assert f"{fake_topic}=enum:{fake_infra}," in fields
    assert f"{fake_points}=number" in fields
    assert "state=state" in fields


def test_tine_formula_fields_names_and_strings_are_faked():
    out = anon('tine.formula.plan:: if(hours > 3, "focus block", formula.effort)')
    key, value = key_and_value(out)
    assert key.startswith("tine.formula.") and key != "tine.formula.plan"
    assert value.startswith("if(") and "hours" not in value and "focus block" not in value
    assert f"formula.{fake_property_key(SALT, 'effort', POLICY)})" in value


def test_tine_group_by_and_aggregates_follow_the_faked_key():
    fake = fake_property_key(SALT, "estimate", POLICY)
    assert anon("tine.group-by:: prop:estimate") == f"tine.group-by:: prop:{fake}"
    assert anon("tine.col-aggregates:: prop:estimate=sum;0=count") == f"tine.col-aggregates:: prop:{fake}=sum;0=count"


def test_query_properties_keep_columns_and_fake_custom_keys():
    out = anon("query-properties:: [:page :companies]")
    assert out == f"query-properties:: [:page :{fake_property_key(SALT, 'companies', POLICY)}]"


def test_asset_path_values_keep_their_directory():
    value = key_and_value(anon("banner:: ../assets/Greek_1694974319845_0.jpg"))[1]
    assert value.startswith("../assets/") and "Greek" not in value
    value = key_and_value(anon("file-path:: G:/My Drive/CBS/KLCM/The Transparency Paradox.pdf"))[1]
    assert "Transparency" not in value and value.endswith(".pdf")


def test_local_link_keeps_only_a_known_file_extension():
    out = anon("- [Directory link](D:/Courses\\50 Projects/[TutsNode.com] - 50 Projects In 50 Days)")
    assert "Projects" not in out and "TutsNode" not in out
    assert ".dk" not in anon("- [Site](milgumor.dk)")
    assert anon("- [Paper](../assets/My_Secret_Paper.pdf)").endswith(".pdf)")


def test_user_text_builtins_keep_the_key_and_fake_the_value():
    assert anon("template:: eisenhower-matrix").startswith("template:: ")
    assert "eisenhower" not in anon("template:: eisenhower-matrix")


def test_property_value_function_matches_enum_faking():
    assert anonymize_property_value(SALT, "topic", "infra", POLICY, False) == key_and_value(anon("topic:: infra"))[1]


def test_config_edn_scrub_fakes_favorites_and_drops_comments():
    edn = ('{:favorites ["contents" "Silicon Sampling Startup"] ; my secret\n :default-home {:page "Contents"}\n'
           ' :block-hidden-properties #{:hidden}\n :x "a;b"}')
    out = scrub_config_edn(SALT, edn, POLICY)
    assert "Silicon" not in out and "secret" not in out
    assert '"a;b"' in out
    assert f"#{{:{fake_property_key(SALT, 'hidden', POLICY)}}}" in out
    assert ":favorites [" in out and ":default-home {:page \"" in out


def test_short_page_names_never_share_a_fake():
    names = [f"{a}{b}{c}" for a in "ABCDEFGHIJ" for b in "KLMNOPQRST" for c in "UVWXYZ"]
    fakes = {anonymize_page_ref(SALT, n).lower() for n in names}
    assert len(fakes) == len(names)
    assert anonymize_page_ref(SALT, "seo") == anonymize_page_ref(SALT, "SEO")


def test_schema_major_mismatch_exits():
    with pytest.raises(SystemExit):
        check_schema_version("2.0.0", "x.yaml")
