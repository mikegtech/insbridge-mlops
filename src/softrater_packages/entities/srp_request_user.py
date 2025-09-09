"""SRP Request User Entity Module."""

from pydantic import BaseModel, ConfigDict


class SrpRequestUser(BaseModel):
    """SRP Request User Entity."""

    user_name: str
    full_name: str
    email_address: str
    model_config = ConfigDict(extra="ignore", from_attributes=True)
