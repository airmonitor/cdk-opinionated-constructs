"""TBD."""

import aws_cdk.aws_ssm as ssm


def count_characters_number(values: dict[list, dict]) -> int:
    """Counts the number of characters in the values.

    Parameters:
        - values: The environment configuration properties.

    Returns:
      - The number of characters.
    """

    total_value_characters = sum(len(str(v)) for v in values.values())
    total_key_characters = sum(len(str(v)) for v in values)
    return total_key_characters + total_value_characters


def reduce_items_number(
    values: dict[list, dict], standard_character_number: int = 4096
) -> dict[list, dict] | dict[str, str]:
    """Counts the number of characters in the values.

    Parameters:
        - values: The environment configuration properties.
        - standard_character_number: The standard number of characters.

    Returns:
      - A Dict with the reduced number of items.
    """

    char_count = count_characters_number(values)

    if char_count <= standard_character_number:
        return values

    return {"dummy": "value"}


def set_ssm_parameter_tier_type(*, character_number: int) -> ssm.ParameterTier:
    """Sets the tier type of the parameter based on the total characters of the
    key and value.

    Parameters:
        - values: The environment configuration properties.

    Returns:
      - The tier type.
    """

    tier_type = ssm.ParameterTier.STANDARD
    if 4069 >= character_number <= 8192:
        tier_type = ssm.ParameterTier.ADVANCED
    return tier_type
