"""Unit tests for GovernanceVars budget filter configuration."""

import pydantic
import pytest

from cdk_opinionated_constructs.schemas.configuration_vars import GovernanceVars

BASE_PROPS = {
    "alarm_emails": ["alarms@example.com"],
    "plugins": {},
    "project": "demo",
    "stage": "ppe",
    "budget_limit_monthly": 30,
}
PROJECT_TAGS = {"tr:project-name": "demo", "tr:environment-type": "ppe", "tr:application-asset-insight-id": 204727}


def test_budget_filter_tag_keys_default_to_none():
    """Without budget_filter_tag_keys the legacy awsApplication filter stays in use."""
    governance_vars = GovernanceVars(
        **BASE_PROPS, tags={"awsApplication": "arn:aws:resource-groups:eu-west-1:1:group/a"}
    )

    assert governance_vars.budget_filter_tag_keys is None  # nosec B101
    assert governance_vars.tags.awsApplication == "arn:aws:resource-groups:eu-west-1:1:group/a"  # nosec B101


def test_tag_values_keep_arbitrary_tags_as_strings():
    """Tags other than awsApplication are kept and exposed as strings."""
    governance_vars = GovernanceVars(
        **BASE_PROPS, tags=PROJECT_TAGS, budget_filter_tag_keys=["tr:project-name", "tr:environment-type"]
    )

    assert governance_vars.tag_values == {  # nosec B101
        "tr:project-name": "demo",
        "tr:environment-type": "ppe",
        "tr:application-asset-insight-id": "204727",
    }


def test_budget_filter_tag_keys_must_exist_in_tags():
    """A budget filter key without a tag value is rejected instead of producing an empty budget."""
    with pytest.raises(pydantic.ValidationError, match=r"budget_filter_tag_keys not found in tags: \['missing'\]"):
        GovernanceVars(**BASE_PROPS, tags=PROJECT_TAGS, budget_filter_tag_keys=["tr:project-name", "missing"])
