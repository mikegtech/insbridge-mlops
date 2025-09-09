"""SRP Request Entity Module."""

from pydantic import BaseModel, ConfigDict

from softrater_packages.entities.srp_request_user import SrpRequestUser


class SrpRequest(BaseModel):
    """SRP Request Entity."""

    schema: str | None = None
    prog_key: str | None = None
    build_type: str
    location: str
    carrier_id: str
    carrier_name: str
    line_id: str
    line_desc: str
    schema_id: str
    program_id: str
    program_name: str
    version_desc: str | None = None
    program_version: str
    parent_company: str
    notes: str | None = None
    date_created_split: str | None = None
    date_created: str | None = None

    model_config = ConfigDict(extra="ignore", from_attributes=True)


class Srp(BaseModel):
    """SRP Entity."""

    srpheader: SrpRequest
    srpuser: SrpRequestUser | None = None
    model_config = ConfigDict(extra="ignore", from_attributes=True)
