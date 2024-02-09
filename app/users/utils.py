
def validate_password(value):
    """
    Validates the password based on the following criteria:
    - Password must have at least 8 characters
    - Password must have at least one uppercase letter
    - Password must have at least one lowercase letter
    - Password must have at least one digit

    Args:
        value (str): The password to be validated.

    Raises:
        ValueError: If the password does not meet the validation criteria.

    Returns:
        str: The validated password.
    """
    # convert the password to a string if it is not already
    value = str(value)
    # check that the password has at least 8 characters, one uppercase letter, one lowercase letter, and one digit
    if len(value) < 8:
        raise ValueError("Password must have at least 8 characters")
    if not any(c.isupper() for c in value):
        raise ValueError("Password must have at least one uppercase letter")
    if not any(c.islower() for c in value):
        raise ValueError("Password must have at least one lowercase letter")
    if not any(c.isdigit() for c in value):
        raise ValueError("Password must have at least one digit")
    return value