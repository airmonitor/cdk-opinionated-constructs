"""Validate variables against pydantic models."""

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, EmailStr, PositiveFloat, constr, model_validator


class Observability(BaseModel):
    """Defines the Observability model.

    Parameters:
      - None

    Attributes:

      - LOG_LEVEL (Literal["DEBUG", "INFO", "ERROR", "CRITICAL", "WARNING", "EXCEPTION"]):
        The log level to use.

      - LOG_SAMPLING_RATE (PositiveFloat):
        The log sampling rate.

    Functionality:

      - Defines a Pydantic model for observability configuration.
      - Constrains LOG_LEVEL to a set of literal string values.
      - Constrains LOG_SAMPLING_RATE to be a positive float.
    """

    LOG_LEVEL: Literal["DEBUG", "INFO", "ERROR", "CRITICAL", "WARNING", "EXCEPTION"]
    LOG_SAMPLING_RATE: PositiveFloat


class PipelinePluginsVars(BaseModel):
    """Defines the PipelinePluginsVars model.

    Parameters:
      - None

    Attributes:

      - pipeline_trigger (bool | None): Whether to enable the pipeline trigger plugin.
      optional.

      - pipeline_trigger_ssm_parameters (list | None): List of SSM parameters to trigger the pipeline.
      optional.

    Functionality:

      - defines a Pydantic model for pipeline plugins configuration.
      - pipeline_trigger enables/disables the pipeline trigger plugin.
      - pipeline_trigger_ssm_parameters configures SSM parameters that will trigger the pipeline when changed.
      - all attributes are optional.
    """

    pipeline_trigger: bool | None = None
    pipeline_trigger_ssm_parameters: list | None = None


class ConfigurationVars(PipelinePluginsVars):
    """Defines the ConfigurationVars model.

    This model extends PipelinePluginsVars and adds additional configuration variables.

    Attributes:

      - alarm_emails (list[EmailStr]): List of emails to receive alarm notifications.

      - plugins (PipelinePluginsVars): Pipeline plugins configuration.

      - project (str): The name of the project.

      - stage (str): The deployment stage.
    """

    alarm_emails: list[EmailStr]
    plugins: PipelinePluginsVars
    project: str
    stage: str


class ApplicationTags(BaseModel):
    """Defines the ApplicationTags model.

    This model represents the tags associated with an AWS application. Any tag key is accepted, so tags referenced
    by GovernanceVars.budget_filter_tag_keys can be validated and read.

    Attributes:
        awsApplication (constr | None): The ARN of the myApplications AWS Resource Group, which must match a specific
        pattern. This field is optional and kept for backward compatibility (myApplications is deprecated).
    """

    model_config = ConfigDict(extra="allow")

    awsApplication: constr(pattern=r"^arn:aws:resource-groups:*") | None = None  # type: ignore


class GovernanceVars(ConfigurationVars):
    """Defines the GovernanceVars model.

    This model extends ConfigurationVars and adds governance-specific configuration variables.

    Attributes:

      - budget_limit_monthly (int | None): The monthly budget limit.

      - budget_filter_tag_keys (list[str] | None): Tag keys whose configured values must all match (AND) for a cost
        to count towards the budgets, e.g. ["tr:project-name", "tr:environment-type"]. The keys must be present in
        tags and activated as cost allocation tags. When not set, budgets fall back to the awsApplication tag.

      - tags (ApplicationTags): The tags to apply to the application.
    """

    budget_limit_monthly: int | None = None
    budget_filter_tag_keys: list[str] | None = None
    tags: ApplicationTags

    @model_validator(mode="after")
    def check_budget_filter_tag_keys(self) -> Self:
        """Ensure every budget filter tag key has a value in tags."""
        if missing := [key for key in self.budget_filter_tag_keys or () if key not in self.tag_values]:
            raise ValueError(f"budget_filter_tag_keys not found in tags: {missing}")
        return self

    @property
    def tag_values(self) -> dict[str, str]:
        """Return all tags as strings, keyed by tag key."""
        return {key: str(value) for key, value in self.tags.model_dump(exclude_none=True).items()}


class NotificationVars(BaseModel):
    """Defines the NotificationVars model.

    Functionality:
        - Represents configuration variables for notification services.
        - Inherits from pydantic's BaseModel for data validation.
        - All fields are optional and can be None.
        - Provides fields for both Slack and Microsoft Teams notification configurations.

    Arguments:
        slack_channel_id_alarms (str | None): The ID of the Slack channel for alarms.
        slack_workspace_id (str | None): The ID of the Slack workspace.
        ms_teams_team_id (str | None): The ID of the Microsoft Teams team.
        ms_teams_channel_id_alarms (str | None): The ID of the Microsoft Teams channel.
        ms_teams_tenant_id (str | None): The ID of the Microsoft Teams tenant.
    """

    slack_channel_id_alarms: str | None = None
    slack_workspace_id: str | None = None
    ms_teams_team_id: str | None = None
    ms_teams_channel_id_alarms: str | None = None
    ms_teams_tenant_id: str | None = None
