"""Validate variables against pydantic models."""

from typing import Literal

from pydantic import BaseModel, EmailStr, PositiveFloat


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

    Parameters:
      - None

    Attributes:

      - stage (Literal["dev", "ppe", "prod", "dr"]): The deployment stage.
      constrained to "dev", "ppe", "prod" or "dr".

      - alarm_emails (list[EmailStr]): A list of emails to receive alarm notifications.

      - project (str): The project name.

    Functionality:

      - extends the PipelineVars model with additional configuration attributes.
      - Constrains stage to a predefined set of options.
      - Allows configuring multiple alarm notification emails.
    """

    project: str
    stage: Literal["dev", "ppe", "prod", "dr"]
    alarm_emails: list[EmailStr]
    plugins: PipelinePluginsVars


class NotificationVars(BaseModel):
    """Defines the NotificationVars model.

    Parameters:
      - None

    Attributes:

      - slack_channel_id_alarms (constr | None): Optional Slack channel for alarm notifications.
      constrained to 11 characters.

      - slack_workspace_id (constr): Required Slack workspace ID. Constrained to 11 characters.

    Functionality:

      - defines a Pydantic model for notification configuration.
      - Allows configuring different Slack channels for alarms and general notifications.
      - slack_workspace_id is required.
      other attributes are optional.
    """

    slack_channel_id_alarms: str
    slack_workspace_id: str | None = None
