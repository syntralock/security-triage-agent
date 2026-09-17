"""Typed, provider-neutral entity references used for alert scoping."""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, IPvAnyAddress

from security_triage_agent.domain._base import DomainModel, Identifier


class EntityType(StrEnum):
    """Entity kinds currently understood by alert scope checks."""

    USER = "USER"
    DEVICE = "DEVICE"
    IP_ADDRESS = "IP_ADDRESS"


class UserEntityReference(DomainModel):
    """Reference to a normalized user identity."""

    entity_type: Literal[EntityType.USER] = EntityType.USER
    identifier: Identifier

    @property
    def scope_key(self) -> str:
        return f"{self.entity_type.value}:{self.identifier}"


class DeviceEntityReference(DomainModel):
    """Reference to a normalized device identity."""

    entity_type: Literal[EntityType.DEVICE] = EntityType.DEVICE
    identifier: Identifier

    @property
    def scope_key(self) -> str:
        return f"{self.entity_type.value}:{self.identifier}"


class IpAddressEntityReference(DomainModel):
    """Reference to a normalized IPv4 or IPv6 address."""

    entity_type: Literal[EntityType.IP_ADDRESS] = EntityType.IP_ADDRESS
    identifier: IPvAnyAddress

    @property
    def scope_key(self) -> str:
        return f"{self.entity_type.value}:{self.identifier}"


type EntityReference = Annotated[
    UserEntityReference | DeviceEntityReference | IpAddressEntityReference,
    Field(discriminator="entity_type"),
]
