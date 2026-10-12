"""Pydantic models for the SAP S/4HANA OData APIs used by the SAP class (see sap.py).

The module contains:
* Field types and helpers for SAP / OData formats (e.g. OData V2 "/Date(...)/" dates,
  SAP flags "X" / "", fixed-length item numbers).
* Base classes: SAPODataModel (all SAP entity models) and SAPODataCreateModel
  (models that are converted into the payload of a deep insert / deep create).
* Models describing OData services, their availability and SAP error responses.
* Create models (e.g. SAPMaintenanceOrderModel) - validated input data that is
  converted into the OData payload with to_odata().
* Response models (e.g. SAPMaintenanceOrderResponseModel) - typed results of read requests.

The Python attribute names of the models are snake case, the aliases are the OData
property names of the SAP APIs. Both can be used to initialize the models.

See sap.py for the documentation of the SAP APIs and how to activate them.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2026, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, timezone
from datetime import time as dtime
from decimal import Decimal
from enum import StrEnum
from functools import partial
from typing import Annotated, ClassVar, Literal, Self, get_origin

import requests
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    TypeAdapter,
    WithJsonSchema,
    computed_field,
    model_validator,
)
from pydantic.json_schema import SkipJsonSchema

# OData V2 JSON format for Edm.DateTime and Edm.DateTimeOffset values:
# "/Date(<milliseconds since 1970-01-01 UTC>[+|-<offset in minutes>])/", e.g. "/Date(1724354331000+0000)/".
# This is the general OData V2 format (not SAP specific). OData V4 uses ISO 8601 instead.
ODATA_V2_DATE_PATTERN = re.compile(r"^/Date\((-?\d+)([+-]\d+)?\)/$")

# OData V2 JSON format for Edm.Time values (an ISO 8601 duration), e.g. "PT08H30M00S":
ODATA_V2_TIME_PATTERN = re.compile(r"^PT(\d{1,2})H(\d{1,2})M(\d{1,2})S$")

# ---------------------------------------------------------------------------
# Field types and helpers for SAP / OData formats
# ---------------------------------------------------------------------------


def parse_odata_datetime(value: str | datetime | None) -> str | datetime | None:
    """Convert an OData V2 JSON date ("/Date(<ms>[+|-<offset>])/") into a timezone-aware datetime.

    Used as a pydantic "before" validator (see ODataDateTime). Other values
    (datetime objects, ISO 8601 strings, None) are passed through unchanged
    and handled by pydantic's standard datetime parsing.

    The milliseconds are always counted from 1970-01-01 UTC. The optional offset
    is given in minutes (e.g. "+0120" = UTC+02:00) and only determines the timezone
    of the result, not the point in time. Values without offset (Edm.DateTime) are
    returned in UTC.

    Args:
        value (str | datetime | None):
            The value to convert, e.g. "/Date(1724354331000+0000)/".

    Returns:
        str | datetime | None:
            The timezone-aware datetime (e.g. 2024-08-22 19:18:51+00:00) for OData V2
            dates, otherwise the unchanged value.

    Raises:
        ValueError:
            If the value looks like an OData V2 date but is malformed.

    """

    if not isinstance(value, str) or not value.startswith("/Date("):
        return value

    match = ODATA_V2_DATE_PATTERN.match(value)
    if not match:
        message = "Invalid OData V2 date value -> '{}'".format(value)
        raise ValueError(message)

    milliseconds, offset_minutes = match.groups()
    result = datetime.fromtimestamp(int(milliseconds) / 1000, tz=UTC)
    if offset_minutes:
        result = result.astimezone(timezone(timedelta(minutes=int(offset_minutes))))

    return result


# end function definition


def serialize_odata_datetime(value: datetime | None) -> str | None:
    """Serialize a datetime in the OData V2 JSON format for Edm.DateTimeOffset ("/Date(<ms>+0000)/").

    Args:
        value (datetime | None):
            The datetime to serialize. Datetimes without timezone are treated as UTC.

    Returns:
        str | None:
            The OData V2 JSON datetime (in UTC) or None.

    """

    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)

    return "/Date({}+0000)/".format(int(value.timestamp() * 1000))


# end function definition


def parse_odata_date(value: str | date | None) -> str | date | None:
    """Convert an OData V2 JSON date ("/Date(<ms of midnight UTC>)/") into a date.

    Used as a pydantic "before" validator (see ODataDate) for Edm.DateTime
    properties with date semantics. Other values (date objects, ISO 8601
    strings, None) are passed through unchanged.

    Args:
        value (str | date | None):
            The value to convert, e.g. "/Date(1791504000000)/".

    Returns:
        str | date | None:
            The date for OData V2 dates, otherwise the unchanged value.

    """

    parsed = parse_odata_datetime(value) if isinstance(value, str) else value

    return parsed.date() if isinstance(parsed, datetime) else parsed


# end function definition


def serialize_odata_date(value: date | None) -> str | None:
    """Serialize a date in the OData V2 JSON format for Edm.DateTime ("/Date(<ms of midnight UTC>)/").

    Args:
        value (date | None):
            The date to serialize.

    Returns:
        str | None:
            The OData V2 JSON date or None.

    """

    if value is None:
        return None

    return "/Date({})/".format(int(datetime(value.year, value.month, value.day, tzinfo=UTC).timestamp() * 1000))


# end function definition


def parse_odata_time(value: str | dtime | None) -> str | dtime | None:
    """Convert an OData V2 JSON time (Edm.Time, e.g. "PT08H30M00S") into a time.

    Other values (time objects, ISO 8601 strings like "08:30", None) are passed
    through unchanged and handled by pydantic's standard time parsing.

    Args:
        value (str | dtime | None):
            The value to convert.

    Returns:
        str | dtime | None:
            The time for OData V2 times, otherwise the unchanged value.

    """

    match = ODATA_V2_TIME_PATTERN.match(value) if isinstance(value, str) else None
    if not match:
        return value
    hours, minutes, seconds = (int(part) for part in match.groups())

    return dtime(hours, minutes, seconds)


# end function definition


def serialize_odata_time(value: dtime | None) -> str | None:
    """Serialize a time in the OData V2 JSON format for Edm.Time (ISO 8601 duration, e.g. "PT08H30M00S").

    Args:
        value (dtime | None):
            The time to serialize.

    Returns:
        str | None:
            The OData V2 JSON time or None.

    """

    return value.strftime("PT%HH%MM%SS") if value else None


# end function definition


def parse_sap_flag(value: str | bool | None) -> bool | None:
    """Convert an SAP flag ("X" = true, "" = false) into a boolean.

    Booleans (e.g. OData V4 Edm.Boolean values) and None are passed through unchanged.

    Args:
        value (str | bool | None):
            The value to convert.

    Returns:
        bool | None:
            The boolean value or None.

    """

    if isinstance(value, str):
        return value.strip().upper() == "X"

    return value


# end function definition


def serialize_sap_flag(value: bool | None) -> str | None:
    """Serialize a boolean as SAP flag ("X" = true, "" = false).

    Args:
        value (bool | None):
            The value to serialize.

    Returns:
        str | None:
            "X", "" or None.

    """

    return None if value is None else ("X" if value else "")


# end function definition


def unwrap_odata_navigation(value: dict | list | None) -> list | None:
    """Unwrap the OData V2 representation of a to-many navigation property.

    Used as a pydantic "before" validator. SAP returns {"__deferred": {"uri": ...}}
    if the navigation property was not expanded and {"results": [...]} if it was
    expanded with $expand. OData V4 returns plain lists (or omits the property if
    not expanded), which are passed through.

    Args:
        value (dict | list | None):
            The raw value of the navigation property.

    Returns:
        list | None:
            The list of child entities or None if they have not been expanded.

    """

    if isinstance(value, dict):
        if "__deferred" in value:
            return None
        return value.get("results", [])

    return value


# end function definition


def pad_number(value: str | int, length: int) -> str:
    """Normalize an SAP item / sequence number (NUMC) to its fixed length (e.g. 10 -> '00010').

    Args:
        value (str | int):
            The number, e.g. 10 or "10".
        length (int):
            The fixed length of the SAP field, e.g. 5 for purchase order items.

    Returns:
        str:
            The number padded with leading zeros.

    Raises:
        ValueError:
            If the value is not numeric or too long.

    """

    value = str(value).strip()
    if not value.isdigit() or len(value) > length:
        message = "Must be numeric with up to {} digits, got -> '{}'".format(length, value)
        raise ValueError(message)

    return value.zfill(length)


# end function definition


def is_empty(value: list) -> bool:
    """Return True if a list of child entities is empty (used with Field(exclude_if=...)).

    Empty child lists are excluded from create payloads - SAP would otherwise try
    to deep insert nothing.

    Args:
        value (list):
            The list of child entities.

    Returns:
        bool:
            True if the list is empty.

    """

    return not value


# end function definition


def unique_numbers(attribute: str) -> AfterValidator:
    """Return a validator that checks that the given (item) number is unique within a list of child entities.

    Args:
        attribute (str):
            The name of the number attribute of the child entities, e.g. "item".

    Returns:
        AfterValidator:
            A pydantic validator to be used in an Annotated list type, e.g.
            Annotated[list[SAPSalesOrderItemModel], unique_numbers("item")].

    """

    def check(children: list) -> list:
        duplicates = sorted(
            number for number, count in Counter(getattr(child, attribute) for child in children).items() if count > 1
        )
        if duplicates:
            message = "Numbers must be unique, duplicates -> {}".format(duplicates)
            raise ValueError(message)
        return children

    return AfterValidator(check)


# end function definition

# Fixed-length SAP numbers (NUMC) - given as int or str and padded with leading zeros:
Numc2 = Annotated[str, BeforeValidator(partial(pad_number, length=2))]
Numc4 = Annotated[str, BeforeValidator(partial(pad_number, length=4))]
Numc5 = Annotated[str, BeforeValidator(partial(pad_number, length=5))]
Numc6 = Annotated[str, BeforeValidator(partial(pad_number, length=6))]

# An SAP code / key (e.g. plant, order type, material) - SAP stores these in upper case:
SAPCode = Annotated[str, StringConstraints(strip_whitespace=True, to_upper=True)]

# A quantity / amount. SAP (OData V4) transfers decimals as strings to avoid rounding errors,
# but the JSON schema shows a plain number - easier to fill for API clients and LLMs:
SAPDecimal = Annotated[Decimal, WithJsonSchema({"type": "number"})]

# An SAP flag ("X" = true, "" = false) in response models - read as boolean:
SAPFlag = Annotated[bool | None, BeforeValidator(parse_sap_flag)]
# An SAP flag in OData V2 create models - additionally serialized as "X" / "":
SAPFlagV2 = Annotated[
    bool | None,
    BeforeValidator(parse_sap_flag),
    PlainSerializer(serialize_sap_flag, when_used="json"),
]

# Types for response models - accept the OData V2 JSON formats in addition to the standard formats:
ODataDateTime = Annotated[datetime | None, BeforeValidator(parse_odata_datetime)]
ODataDate = Annotated[date | None, BeforeValidator(parse_odata_date)]
ODataTime = Annotated[dtime | None, BeforeValidator(parse_odata_time)]

# Types for OData V2 create models - additionally serialized in the OData V2 JSON formats:
ODataV2DateTime = Annotated[
    datetime | None,
    BeforeValidator(parse_odata_datetime),
    PlainSerializer(serialize_odata_datetime, when_used="json"),
]
ODataV2Date = Annotated[
    date | None,
    BeforeValidator(parse_odata_date),
    PlainSerializer(serialize_odata_date, when_used="json"),
]
ODataV2Time = Annotated[
    dtime | None,
    BeforeValidator(parse_odata_time),
    PlainSerializer(serialize_odata_time, when_used="json"),
]

# ---------------------------------------------------------------------------
# Base classes
# ---------------------------------------------------------------------------


class SAPODataModel(BaseModel):
    """Base class of all models for SAP OData entities.

    The Python attribute names are snake case. The aliases are the OData property
    names of the SAP API. Both can be used to initialize the models. Default values
    are validated as well (e.g. item numbers are padded to their SAP length).

    OData properties that are not modelled are ignored in the response models: SAP
    returns many technical properties (often in raw OData formats like "/Date(...)/")
    that would only be noise for users or LLMs. Model a property to return it.
    The create models keep them instead (see SAPODataCreateModel).

    """

    model_config = ConfigDict(
        validate_by_name=True,
        validate_by_alias=True,
        validate_default=True,
        extra="ignore",
        # Readable titles in the JSON schema ("Basic start datetime") instead of
        # titles derived from the OData names ("Maintordbasicstartdatetime"):
        field_title_generator=lambda name, _info: name.replace("_", " ").capitalize(),
    )

    @model_validator(mode="before")
    @classmethod
    def drop_odata_annotations(cls, data: object) -> object:
        """Drop OData protocol annotations that carry no business data.

        These are "__metadata" (OData V2), "@odata.context" / "@odata.etag" (OData V4)
        and navigation properties that have not been expanded ({"__deferred": ...}).
        Otherwise the create models would keep them as extra fields (extra="allow")
        and send them back to SAP.

        """

        if not isinstance(data, dict):
            return data

        return {
            key: value
            for key, value in data.items()
            if not key.startswith(("__", "@")) and not (isinstance(value, dict) and "__deferred" in value)
        }

    # end method definition

    def __repr__(self) -> str:
        """Return the entity as compact JSON with the OData property names, without empty (None) values.

        This is also what str() returns - for single models and for lists of models
        (str(list) uses the repr of the elements). So SAP entities can be passed as they
        are to consumers that convert objects with str() - e.g. LangChain tools returning
        these models to an LLM: the LLM sees the same OData names that it has to use in
        filter expressions and changes, instead of Python attribute names and reprs like
        "datetime.datetime(2026, 11, 2, 8, 0)".

        """

        return self.model_dump_json(by_alias=True, exclude_none=True)

    # end method definition

    __str__ = __repr__


class SAPODataCreateModel(SAPODataModel):
    """Base class of the models used to create SAP documents (deep insert / deep create).

    Serialization uses the OData property names (aliases), so to_odata() returns the
    payload as expected by the SAP API. Additional OData properties that are not
    modelled can be passed with their OData name (e.g. "ResponsibleCostCenter") and
    are sent as they are (kept as extra fields, see model_extra).

    """

    model_config = ConfigDict(serialize_by_alias=True, extra="allow")

    @model_validator(mode="before")
    @classmethod
    def check_unknown_fields(cls, data: object) -> object:
        """Reject unknown lower case keys - they are misspelled attribute names, not OData properties.

        Additional OData properties that are not modelled can still be passed with their
        OData name (these start with an upper case letter), see to_odata_update().

        """

        if not isinstance(data, dict):
            return data

        known = set(cls.model_fields) | {field.alias for field in cls.model_fields.values() if field.alias}
        unknown = sorted(key for key in data if key not in known and key[:1].islower())
        if unknown:
            message = "Unknown field(s) -> {} for {}".format(unknown, cls.__name__)
            raise ValueError(message)

        return data

    # end method definition

    def to_odata(self) -> dict:
        """Return the OData payload (deep insert / deep create) of the document.

        Returns:
            dict:
                The payload with OData property names. Unset (None) values and empty
                child lists are omitted so SAP can apply its defaults. Decimals are
                serialized as strings (OData V4 APIs require the IEEE754Compatible=true
                content type for this).

        """

        return self.model_dump(exclude_none=True, mode="json")

    # end method definition

    @classmethod
    def to_odata_update(cls, changes: dict) -> dict:
        """Return the OData payload to update (PATCH) individual fields of an existing document.

        Each changed value is validated and serialized with the definition of the
        corresponding field of this model (type, length, upper case, SAP / OData
        formats) - so updates get the same treatment as creates. Validations that
        span several fields (e.g. "end date after start date") are not applied, as
        the other fields of the document are not known.

        Args:
            changes (dict):
                The fields to change - with snake case attribute names or OData
                property names, e.g. {"description": "New text"} or
                {"MaintenanceOrderDesc": "New text"}. OData properties that are not
                modelled can be passed with their OData name and are sent as is.

        Returns:
            dict:
                The payload with OData property names.

        Raises:
            ValueError:
                If a field is unknown, refers to child entities (e.g. items) or
                has an invalid value (pydantic.ValidationError is a ValueError).

        Example:
            >>> SAPSalesOrderModel.to_odata_update({"requested_delivery_date": "2026-12-01"})
            {'RequestedDeliveryDate': '/Date(1796083200000)/'}

        """

        fields = {}
        for name, field in cls.model_fields.items():
            fields[name] = field
            if field.alias:
                fields[field.alias] = field

        payload = {}
        for key, value in changes.items():
            field = fields.get(key)
            if field is None:
                # OData property names start with an upper case letter - a lower case
                # key is most likely a misspelled attribute name:
                if key[:1].islower():
                    message = "Unknown field -> '{}' for {}".format(key, cls.__name__)
                    raise ValueError(message)
                payload[key] = value
                continue
            if get_origin(field.annotation) is list:
                message = "Field -> '{}' refers to child entities which cannot be changed with an update".format(key)
                raise ValueError(message)
            adapter = TypeAdapter(Annotated[field.annotation, *field.metadata] if field.metadata else field.annotation)
            payload[field.alias or key] = adapter.dump_python(adapter.validate_python(value), mode="json")

        return payload

    # end method definition


class SAPPurchasingItemModel(SAPODataCreateModel):
    """Base class of the items of purchasing documents (purchase order, contract and requisition).

    Provides the fields and validations common to all purchasing document items.
    The subclasses add the item specific fields (e.g. the short text, whose OData
    name differs per document type).

    Contract with the subclasses (the validations access these fields by name):
    * item (required): the item number - used in error messages.
    * text (required): the short text - without it, a material is always required.
    * account_assignments (optional): the account assignments - items without
      this field (e.g. purchase contract items) skip the account assignment check.

    """

    material: SAPCode | None = Field(
        default=None,
        alias="Material",
        description="Material (product) number, e.g. 'TG11'. Required unless `text` and `material_group` are given.",
        max_length=40,
    )
    material_group: SAPCode | None = Field(
        default=None,
        alias="MaterialGroup",
        description="Material group, e.g. 'L001'. Required together with `text` if no `material` is given (e.g. for services or free-text items).",
        max_length=9,
    )
    account_assignment_category: SAPCode | None = Field(
        default=None,
        alias="AccountAssignmentCategory",
        description="Account assignment category, e.g. 'K' (cost center), 'F' (internal order), 'P' (project). Required if `account_assignments` are given - system specific; copy from an existing document if unsure.",
        max_length=1,
    )

    @model_validator(mode="after")
    def check_material_or_text(self) -> Self:
        """Validate that the item has a material or a short text plus a material group."""

        if not self.material and not (getattr(self, "text", None) and self.material_group):
            message = "Item -> {} needs a material or a text plus a material group".format(getattr(self, "item", "?"))
            raise ValueError(message)

        return self

    # end method definition

    @model_validator(mode="after")
    def check_account_assignments(self) -> Self:
        """Validate that items with account assignments have an account assignment category."""

        if getattr(self, "account_assignments", None) and not self.account_assignment_category:
            message = "Item -> {} has account assignments but no account assignment category".format(
                getattr(self, "item", "?"),
            )
            raise ValueError(message)

        return self

    # end method definition


# ---------------------------------------------------------------------------
# Query models (structured search criteria of the list / iterator methods)
# ---------------------------------------------------------------------------

# Number of entities requested per page when reading collections (client-driven paging
# with $top / $skip). SAP recommends pages of at most a few thousand entities - smaller
# pages keep the responses (especially with $expand) small and fast:
ODATA_PAGE_SIZE = 1000


def odata_literal(
    value: str | bool | float | Decimal | date | datetime,
    odata_version: int = 2,
    kind: Literal["timestamp", "flag"] | None = None,
) -> str:
    """Format a value as OData URI literal (for $filter conditions and function import parameters).

    Args:
        value (str | bool | float | Decimal | date | datetime):
            The Python value.
        odata_version (int, optional):
            The OData version of the service (2 or 4). Defaults to 2.
        kind (Literal["timestamp", "flag"] | None, optional):
            "timestamp" for Edm.DateTimeOffset properties (dates are taken as midnight UTC),
            "flag" for SAP flags in OData V2 services ("X" = true, "" = false). Defaults to None.

    Returns:
        str:
            The literal, e.g. 'ABC' (quotes doubled), true, 'X', datetime'2026-10-10T00:00:00' /
            2026-10-10 (V2 / V4 dates) or datetimeoffset'2026-10-10T08:00:00Z' / 2026-10-10T08:00:00Z
            (V2 / V4 timestamps).

    """

    if isinstance(value, bool):
        if kind == "flag" and odata_version == 2:
            return "'X'" if value else "''"
        return "true" if value else "false"
    if isinstance(value, date) and not isinstance(value, datetime) and kind == "timestamp":
        value = datetime(value.year, value.month, value.day, tzinfo=UTC)
    if isinstance(value, datetime):
        if value.tzinfo is None and odata_version == 2:
            return "datetime'{}'".format(value.strftime("%Y-%m-%dT%H:%M:%S"))
        timestamp = (
            (value if value.tzinfo else value.replace(tzinfo=UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        return "datetimeoffset'{}'".format(timestamp) if odata_version == 2 else timestamp
    if isinstance(value, date):
        return "datetime'{}T00:00:00'".format(value.isoformat()) if odata_version == 2 else value.isoformat()
    if isinstance(value, int | float | Decimal):
        return str(value)

    return "'{}'".format(str(value).replace("'", "''"))


# end function definition


@dataclass(frozen=True)
class ODataCondition:
    """Describes how a field of a query model becomes a condition of the OData $filter.

    Used as metadata of the query model fields, e.g.
    Annotated[SAPCode | None, ODataCondition("MaintenancePlanningPlant")].
    Fields that are None (or empty lists) are not part of the filter.

    Attributes:
        property (str | tuple[str, str]):
            The OData property, e.g. "MaintenancePlanningPlant". For the operator "valid_on"
            the properties of the start and the end of the validity period.
        operator (Literal["eq", "ge", "le", "contains", "valid_on"]):
            "eq" (default - a list of values matches any of them), "ge" / "le" (ranges, a date
            as upper limit of a timestamp property includes the whole day), "contains" (text
            search, case-sensitive in most SAP services) or "valid_on" (start <= date <= end).
        kind (Literal["timestamp", "flag"] | None):
            "timestamp" for Edm.DateTimeOffset properties, "flag" for SAP flags ("X" / "").
        path (str | None):
            Navigation property of a to-many relationship (e.g. "_PurchaseRequisitionItem") for
            conditions on child entities: matches if any child matches. OData V4 only.
        values (dict | None):
            Maps the field values to the OData values, e.g. {"person": "1", "organization": "2"}.

    """

    property: str | tuple[str, str]
    operator: Literal["eq", "ge", "le", "contains", "valid_on"] = "eq"
    kind: Literal["timestamp", "flag"] | None = None
    path: str | None = None
    values: dict | None = None

    def to_filter(self, value: object, odata_version: int) -> str:
        """Return the $filter condition for a field value.

        Args:
            value (object):
                The (not empty) value of the query model field.
            odata_version (int):
                The OData version of the service (2 or 4).

        Returns:
            str:
                The condition, e.g. "(MaintenanceOrderType eq 'YA01' or MaintenanceOrderType eq 'YA02')".

        Raises:
            ValueError:
                If a condition on child entities is used with an OData V2 service.

        """

        prefix = "i/" if self.path else ""

        def literal(single_value: object) -> str:
            return odata_literal(
                self.values.get(single_value, single_value) if self.values else single_value,
                odata_version=odata_version,
                kind=self.kind,
            )

        def condition(single_value: object) -> str:
            name = prefix + self.property if isinstance(self.property, str) else ""
            match self.operator:
                case "contains":
                    if odata_version == 2:
                        return "substringof({}, {})".format(literal(single_value), name)
                    return "contains({}, {})".format(name, literal(single_value))
                case "valid_on":
                    start, end = (prefix + name for name in self.property)
                    return "{} le {} and {} ge {}".format(start, literal(single_value), end, literal(single_value))
                case "le" if self.kind == "timestamp" and not isinstance(single_value, datetime):
                    # A date as upper limit of a timestamp includes the whole day:
                    return "{} lt {}".format(name, literal(single_value + timedelta(days=1)))
                case _:
                    return "{} {} {}".format(name, self.operator, literal(single_value))

        values = value if isinstance(value, list) else [value]
        result = " or ".join(condition(single_value) for single_value in values)
        if len(values) > 1:
            result = "({})".format(result)

        if self.path:
            if odata_version != 4:
                message = "Conditions on child entities ('{}') are only supported by OData V4 services".format(
                    self.path
                )
                raise ValueError(message)
            result = "{}/any(i:{})".format(self.path, result)

        return result

    # end method definition


class SAPODataQueryModel(BaseModel):
    """Base class of the search criteria for SAP OData collections (list and iterator methods).

    The fields of the subclasses are the search criteria. Fields with an ODataCondition in
    their metadata become conditions of the OData $filter (all conditions must match);
    fields that are None (or empty lists) are ignored. The subclasses define:
    * sort_by: the sort criteria, mapped to the $orderby expression with SORT_PROPERTIES.
    * expand_items (optional): whether to read the child entities (with EXPAND).
    * BASE_CONDITIONS (optional): conditions that are always part of the filter.

    """

    model_config = ConfigDict(
        extra="forbid",
        validate_default=True,
        field_title_generator=lambda name, _info: name.replace("_", " ").capitalize(),
    )

    # The $orderby expressions of the sort_by values ("{direction}" is replaced with asc / desc):
    SORT_PROPERTIES: ClassVar[dict[str, str]] = {}
    # The $expand expression to read the child entities (if expand_items is set):
    EXPAND: ClassVar[str] = ""
    # Conditions that are always part of the filter (e.g. "Customer ne ''"):
    BASE_CONDITIONS: ClassVar[list[str]] = []

    limit: int | None = Field(default=None, ge=1, description="Maximum number of results. None = all results.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    # Transport setting - not part of the JSON schema (not relevant for API clients / LLMs):
    page_size: SkipJsonSchema[int] = Field(
        default=ODATA_PAGE_SIZE,
        ge=1,
        le=5000,
        description="Number of entities requested per page (OData $top / $skip paging).",
    )

    def to_odata(self, odata_version: int) -> dict:
        """Return the OData query options ($filter, $orderby, $expand) of the search criteria.

        The limit and the page size are not included - they control the paging (see
        SAP._iter_odata_collection()).

        Args:
            odata_version (int):
                The OData version of the service (2 or 4).

        Returns:
            dict:
                The query options, e.g. {"$filter": "MaintenancePlanningPlant eq '1010'",
                "$orderby": "MaintenanceOrder desc"}.

        """

        conditions = list(self.BASE_CONDITIONS)
        for name, field in type(self).model_fields.items():
            marker = next((item for item in field.metadata if isinstance(item, ODataCondition)), None)
            value = getattr(self, name)
            if marker is None or value is None or value == []:
                continue
            conditions.append(marker.to_filter(value=value, odata_version=odata_version))

        sort_by = getattr(self, "sort_by", None)
        params = {"$orderby": self.SORT_PROPERTIES[sort_by].format(direction=self.sort_direction)} if sort_by else {}
        if conditions:
            params["$filter"] = " and ".join(
                "({})".format(condition) if " or " in condition and not condition.startswith("(") else condition
                for condition in conditions
            )
        if self.EXPAND and getattr(self, "expand_items", False):
            params["$expand"] = self.EXPAND

        return params

    # end method definition


# ---------------------------------------------------------------------------
# OData services, availability check results and errors
# ---------------------------------------------------------------------------


class SAPODataServiceModel(BaseModel):
    """Definition of an SAP OData service (API) used by this module.

    Attributes:
        name (str):
            Technical name of the service, e.g. "API_MAINTENANCEORDER".
        path (str):
            Service root path relative to the SAP base URL,
            e.g. "/sap/opu/odata/sap/API_MAINTENANCEORDER".
        odata_version (int):
            OData protocol version of the service (2 or 4).
        entity_sets (list[str]):
            Entity sets that must be exposed by the service. Used by check_odata_apis()
            to detect services that are active but do not expose what we need
            (e.g. because of an older S/4HANA release).
        description (str):
            Human readable description of the service.

    """

    name: str
    path: str
    odata_version: int = Field(default=2, ge=2, le=4)
    entity_sets: list[str] = Field(default_factory=list)
    description: str = ""


class SAPODataServiceState(StrEnum):
    """Possible results of an OData service availability check."""

    ACTIVE = "active"  # service is reachable and exposes all expected entity sets
    INCOMPLETE = "incomplete"  # service is active but expected entity sets are missing
    NOT_ACTIVATED = "not_activated"  # service is not activated / published in SAP Gateway
    ICF_INACTIVE = "icf_inactive"  # the ICF node of the OData endpoint is not active
    UNAUTHORIZED = "unauthorized"  # authentication failed (wrong user / password / client)
    FORBIDDEN = "forbidden"  # authenticated but not authorized (S_SERVICE)
    UNREACHABLE = "unreachable"  # network / DNS / TLS / timeout problem
    ERROR = "error"  # any other error


class SAPODataServiceStatusModel(BaseModel):
    """Result of the availability check for one SAP OData service.

    Attributes:
        service (SAPODataServiceModel):
            The service that has been checked.
        url (str):
            The URL that has been called for the check.
        state (SAPODataServiceState):
            The result of the check.
        http_status (int | None):
            The HTTP status code. None if the SAP system could not be reached.
        message (str):
            The (error) message returned by SAP or the request library.
        available_entity_sets (list[str]):
            Entity sets exposed by the service (only filled if the service is active).
        missing_entity_sets (list[str]):
            Expected entity sets that are not exposed by the service.
        hint (str):
            A hint how to fix the problem (empty if the service is active).
        active (bool):
            True if the service is active and exposes all expected entity sets
            (computed - also included in model_dump() / model_dump_json()).

    """

    service: SAPODataServiceModel
    url: str
    state: SAPODataServiceState
    http_status: int | None = None
    message: str = ""
    available_entity_sets: list[str] = Field(default_factory=list)
    missing_entity_sets: list[str] = Field(default_factory=list)
    hint: str = ""

    @computed_field
    @property
    def active(self) -> bool:
        """Return True if the service is active and exposes all expected entity sets."""

        return self.state == SAPODataServiceState.ACTIVE

    # end method definition


class SAPODataErrorDetailModel(BaseModel):
    """A single detail message of an SAP OData error response."""

    code: str = ""
    message: str = ""
    severity: str = ""
    target: str = ""


class SAPODataErrorModel(BaseModel):
    """An error returned by an SAP OData service.

    SAP returns errors in different formats depending on the OData version:

    OData V2:
        {"error": {"code": "...", "message": {"lang": "en", "value": "..."},
                   "innererror": {"errordetails": [{"code": "...", "message": "...", "severity": "error"}]}}}

    OData V4:
        {"error": {"code": "...", "message": "...",
                   "details": [{"code": "...", "message": "...", "@Common.Severity": "error"}]}}

    Non-OData errors (e.g. inactive ICF nodes, proxies) are often returned as HTML.

    """

    status_code: int
    code: str = ""
    message: str = ""
    details: list[SAPODataErrorDetailModel] = Field(default_factory=list)
    raw_text: str = ""

    @classmethod
    def from_response(cls, response: requests.Response) -> Self:
        """Build an SAPODataErrorModel from a (failed) HTTP response.

        This method never raises an exception - if the response cannot be
        interpreted, the raw response text is preserved instead.

        Args:
            response (requests.Response):
                The failed HTTP response.

        Returns:
            SAPODataErrorModel:
                The parsed error.

        """

        error = cls(status_code=response.status_code, raw_text=response.text or "")

        try:
            error_body = response.json().get("error", {})
        except (ValueError, AttributeError):
            # Not JSON (e.g. HTML error page) - keep raw text only:
            content_type = (response.headers.get("content-type") or "").lower()
            error.message = "HTML error page returned" if "html" in content_type else (response.text or "")[:500]
            return error

        if not isinstance(error_body, dict):
            return error

        error.code = str(error_body.get("code", ""))
        message = error_body.get("message", "")
        # OData V2 wraps the message in a dict with language and value:
        error.message = message.get("value", "") if isinstance(message, dict) else str(message)

        # OData V2 provides details in "innererror.errordetails", OData V4 in "details":
        raw_details = error_body.get("details") or (error_body.get("innererror") or {}).get("errordetails") or []
        for raw_detail in raw_details:
            if not isinstance(raw_detail, dict):
                continue
            detail_message = raw_detail.get("message", "")
            error.details.append(
                SAPODataErrorDetailModel(
                    code=str(raw_detail.get("code", "")),
                    message=detail_message.get("value", "")
                    if isinstance(detail_message, dict)
                    else str(detail_message),
                    severity=str(raw_detail.get("severity") or raw_detail.get("@Common.Severity") or ""),
                    target=str(raw_detail.get("target") or raw_detail.get("propertyref") or ""),
                ),
            )

        return error

    # end method definition

    def __str__(self) -> str:
        """Return a compact, human readable representation of the error for logging."""

        text = "{}{}".format("[{}] ".format(self.code) if self.code else "", self.message or "(no message)")

        # The target tells which part of the request caused the error, e.g. for a deep insert
        # "to_MaintenanceOrderOperation(MaintenanceOrder='',MaintenanceOrderOperation='0010',...)":
        target = next(
            (detail.target for detail in self.details if detail.target and detail.message == self.message),
            "",
        )
        if target:
            text += " (target -> {})".format(target)

        # Add the other messages, but skip repetitions of the main message and
        # success / info messages (SAP also returns those on errors, they are just noise).
        # dict.fromkeys() removes duplicates while keeping the order:
        details = list(
            dict.fromkeys(
                "{}{}".format("{}: ".format(detail.severity) if detail.severity else "", detail.message)
                for detail in self.details
                if detail.message
                and detail.message != self.message
                and detail.severity.lower() not in ("success", "info")
            ),
        )
        if details:
            text += "; details -> " + " | ".join(details)

        return text

    # end method definition


# ---------------------------------------------------------------------------
# Maintenance orders (API_MAINTENANCEORDER, OData V2)
# ---------------------------------------------------------------------------


class SAPMaintenanceOrderOperationModel(SAPODataCreateModel):
    """An operation of an SAP Plant Maintenance order (API_MAINTENANCEORDER).

    Additional OData properties of the operation that are not modelled here can be
    passed with their OData name (e.g. "PlannedWorkQuantity").

    See: https://api.sap.com/api/API_MAINTENANCEORDER/overview

    """

    operation: Numc4 = Field(
        default="10",
        alias="MaintenanceOrderOperation",
        description="Operation number (4 digits, padded), e.g. 10 -> '0010'. Unique within the order.",
    )
    description: str = Field(
        alias="OperationDescription",
        description="Short text of the operation, e.g. 'Replace seal'.",
        min_length=1,
        max_length=40,
    )
    control_key: SAPCode | None = Field(
        default=None,
        alias="OperationControlKey",
        description="Operation control key. Practically mandatory - the API applies no default and rejects operations without one. E.g. 'PM01' (standard), 'YBM1' (S/4HANA Cloud) - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    work_center: SAPCode | None = Field(
        default=None,
        alias="WorkCenter",
        description="Work center executing the operation, e.g. 'RES-0100'. Defaults to the main work center of the order.",
        max_length=8,
    )
    plant: SAPCode | None = Field(
        default=None,
        alias="Plant",
        description="Plant of the operation's work center, e.g. '1010'.",
        max_length=4,
    )


class SAPMaintenanceOrderModel(SAPODataCreateModel):
    """Data to create an SAP Plant Maintenance order (API_MAINTENANCEORDER).

    Additional OData properties of the order header that are not modelled here can
    be passed with their OData name (e.g. "ResponsibleCostCenter").

    Which fields are mandatory depends on the customizing of the order type in the
    S/4HANA system. Typically, at least an order type, a description, a planning plant,
    a main work center and a reference object (equipment or functional location) are required.

    See: https://api.sap.com/api/API_MAINTENANCEORDER/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "MaintenanceOrderType": "YA01",
                    "MaintenanceOrderDesc": "Replace pump seal",
                    "MaintenancePlanningPlant": "1010",
                    "MainWorkCenter": "RES-0100",
                    "MainWorkCenterPlant": "1010",
                    "Equipment": "210100001",
                    "MaintOrdBasicStartDateTime": "2026-11-02T08:00:00Z",
                    "MaintOrdBasicEndDateTime": "2026-11-02T16:00:00Z",
                    "to_MaintenanceOrderOperation": [
                        {
                            "MaintenanceOrderOperation": "10",
                            "OperationDescription": "Replace seal",
                            "OperationControlKey": "YBM1",
                        }
                    ],
                }
            ]
        }
    )

    order_type: SAPCode = Field(
        alias="MaintenanceOrderType",
        description="Maintenance order type, e.g. 'PM01' (standard) or 'YA01' (S/4HANA Cloud) - system specific; copy from an existing document if unsure.",
        min_length=1,
        max_length=4,
    )
    description: str = Field(
        alias="MaintenanceOrderDesc",
        description="Short text of the order, e.g. 'Replace pump seal'.",
        min_length=1,
        max_length=40,
    )
    planning_plant: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant, e.g. '1010'. Usually required.",
        max_length=4,
    )
    main_work_center: SAPCode | None = Field(
        default=None,
        alias="MainWorkCenter",
        description="Main work center responsible for the order, e.g. 'RES-0100'. Usually required.",
        max_length=8,
    )
    main_work_center_plant: SAPCode | None = Field(
        default=None,
        alias="MainWorkCenterPlant",
        description="Plant of the main work center, e.g. '1010'.",
        max_length=4,
    )
    equipment: SAPCode | None = Field(
        default=None,
        alias="Equipment",
        description="Equipment (technical object) to maintain, e.g. '210100001'. Give this or `functional_location`.",
        max_length=18,
    )
    functional_location: str | None = Field(
        default=None,
        alias="FunctionalLocation",
        description="Internal functional location ID - not the (longer) label shown in the UI. Give this or `equipment`.",
        max_length=30,
    )
    priority: SAPCode | None = Field(
        default=None,
        alias="MaintPriority",
        description="Maintenance priority, e.g. '1' (very high) to '4' (low) - system specific; copy from an existing document if unsure.",
        max_length=1,
    )
    activity_type: SAPCode | None = Field(
        default=None,
        alias="MaintenanceActivityType",
        description="Maintenance activity type, e.g. '001' (inspection), '002' (repair) - system specific; copy from an existing document if unsure.",
        max_length=3,
    )
    planner_group: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlannerGroup",
        description="Maintenance planner group, e.g. '010' - system specific; copy from an existing document if unsure.",
        max_length=3,
    )
    notification: SAPCode | None = Field(
        default=None,
        alias="MaintenanceNotification",
        description="Number of the maintenance notification the order is created for.",
        max_length=12,
    )
    basic_start_datetime: ODataV2DateTime = Field(
        default=None,
        alias="MaintOrdBasicStartDateTime",
        description="Basic start date and time of the order, ISO 8601, e.g. '2026-11-01T08:00:00Z'; without timezone treated as UTC.",
    )
    basic_end_datetime: ODataV2DateTime = Field(
        default=None,
        alias="MaintOrdBasicEndDateTime",
        description="Basic end date and time of the order, ISO 8601, e.g. '2026-11-01T08:00:00Z'; without timezone treated as UTC. Must not be before the start.",
    )
    operations: Annotated[list[SAPMaintenanceOrderOperationModel], unique_numbers("operation")] = Field(
        default_factory=list,
        alias="to_MaintenanceOrderOperation",
        description="Operations (work steps) of the order. Operation numbers must be unique within the order.",
        exclude_if=is_empty,
    )

    @model_validator(mode="after")
    def check_dates(self) -> Self:
        """Validate that the basic end date is not before the basic start date."""

        # Compare as UTC timestamps (naive datetimes are treated as UTC, see serialize_odata_datetime()):
        start, end = (
            value.replace(tzinfo=value.tzinfo or UTC) if value else None
            for value in (self.basic_start_datetime, self.basic_end_datetime)
        )
        if start and end and end < start:
            message = "Basic end date -> {} is before basic start date -> {}".format(
                self.basic_end_datetime,
                self.basic_start_datetime,
            )
            raise ValueError(message)

        return self

    # end method definition


class SAPMaintenanceOrderOperationResponseModel(SAPODataModel):
    """An operation of an SAP Plant Maintenance order as returned by SAP (API_MAINTENANCEORDER).

    In contrast to SAPMaintenanceOrderOperationModel (used to create operations)
    all fields except the keys are optional and dates are converted into
    timezone-aware datetime objects.

    """

    order_id: str = Field(
        alias="MaintenanceOrder", description="Maintenance order number; see get_maintenance_order()."
    )
    operation: str = Field(alias="MaintenanceOrderOperation", description="Operation number (4 digits), e.g. '0010'.")
    sub_operation: str = Field(
        default="", alias="MaintenanceOrderSubOperation", description="Sub-operation number (empty for operations)."
    )
    description: str | None = Field(
        default=None, alias="OperationDescription", description="Short text of the operation."
    )
    control_key: str | None = Field(
        default=None,
        alias="OperationControlKey",
        description="Operation control key, e.g. 'PM01' or 'YBM1' - reuse it when creating operations.",
    )
    work_center: str | None = Field(
        default=None,
        alias="WorkCenter",
        description="Work center - the people or machines (with capacity) that perform the work; see get_work_center().",
    )
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    system_status: str | None = Field(
        default=None,
        alias="SystemStatusText",
        description="Active system statuses as text (abbreviations), e.g. 'REL CNF'.",
    )
    constraint_start_datetime: ODataDateTime = Field(
        default=None,
        alias="MaintOrdOpConstraintStrtDteTme",
        description="Constraint (earliest) start date and time of the operation.",
    )
    constraint_finish_datetime: ODataDateTime = Field(
        default=None,
        alias="MaintOrdOpCstrtFinishDteTme",
        description="Constraint (must finish by) date and time of the operation, timezone-aware.",
    )
    earliest_scheduled_start_datetime: ODataDateTime = Field(
        default=None,
        alias="OpErlstSchedldExecStrtDteTme",
        description="Earliest scheduled start of the operation execution, timezone-aware.",
    )
    earliest_scheduled_end_datetime: ODataDateTime = Field(
        default=None,
        alias="OpErlstSchedldExecEndDteTme",
        description="Earliest scheduled finish of the operation execution, timezone-aware.",
    )
    latest_scheduled_start_datetime: ODataDateTime = Field(
        default=None,
        alias="OpLtstSchedldExecStrtDteTme",
        description="Latest scheduled start of the operation execution, timezone-aware.",
    )
    latest_scheduled_end_datetime: ODataDateTime = Field(
        default=None,
        alias="OpLtstSchedldExecEndDteTme",
        description="Latest scheduled finish of the operation execution, timezone-aware.",
    )
    actual_start_datetime: ODataDateTime = Field(
        default=None,
        alias="OpActualExecutionStartDateTime",
        description="Actual (confirmed) start of the operation execution, timezone-aware.",
    )
    actual_end_datetime: ODataDateTime = Field(
        default=None,
        alias="OpActualExecutionEndDateTime",
        description="Actual (confirmed) finish of the operation execution, timezone-aware.",
    )
    forecasted_end_datetime: ODataDateTime = Field(
        default=None,
        alias="ActyConfForecastedEndDateTime",
        description="Forecasted finish of the operation from the last confirmation, timezone-aware.",
    )
    planned_work: SAPDecimal | None = Field(
        default=None,
        alias="MaintOrdOperationWorkDuration",
        description="Planned work (effort) of the operation - confirm actual work in the same unit.",
    )
    planned_work_unit: str | None = Field(
        default=None, alias="MaintOrdOpWorkDurationUnit", description="Unit of the planned work, e.g. 'H' (hours)."
    )


class SAPMaintenanceOrderResponseModel(SAPODataModel):
    """An SAP Plant Maintenance order as returned by SAP (API_MAINTENANCEORDER).

    In contrast to SAPMaintenanceOrderModel (used to create orders) all fields
    except the order number are optional and dates are converted into
    timezone-aware datetime objects.

    Attributes:
        operations (list[SAPMaintenanceOrderOperationResponseModel] | None):
            The operations of the order. None if the operations have not been
            requested ($expand), an empty list if the order has no operations.

    """

    order_id: str = Field(
        alias="MaintenanceOrder", description="Maintenance order number; see get_maintenance_order()."
    )
    order_type: str | None = Field(
        default=None, alias="MaintenanceOrderType", description="Maintenance order type, e.g. 'PM01' or 'YA01'."
    )
    description: str | None = Field(default=None, alias="MaintenanceOrderDesc", description="Short text of the order.")
    planning_plant: str | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant - the plant whose planner groups plan and schedule the maintenance work.",
    )
    maintenance_plant: str | None = Field(
        default=None,
        alias="MaintenancePlant",
        description="Maintenance plant - the plant in which the technical object is installed.",
    )
    main_work_center: str | None = Field(
        default=None,
        alias="MainWorkCenter",
        description="Main work center - responsible for executing the maintenance work; see get_work_center().",
    )
    main_work_center_plant: str | None = Field(
        default=None, alias="MainWorkCenterPlant", description="Plant of the main work center."
    )
    equipment: str | None = Field(
        default=None,
        alias="Equipment",
        description="Equipment - an individual technical object (e.g. a pump) that is maintained; see get_equipment().",
    )
    functional_location: str | None = Field(
        default=None,
        alias="FunctionalLocation",
        description="Functional location (internal ID) - a place in the technical structure where equipment is installed; see get_functional_location().",
    )
    technical_object: str | None = Field(
        default=None,
        alias="TechnicalObject",
        description="Technical object (equipment or functional location label) as shown in the UI.",
    )
    priority: str | None = Field(
        default=None,
        alias="MaintPriority",
        description="Priority, e.g. '1' (very high) to '4' (low) - system specific.",
    )
    activity_type: str | None = Field(
        default=None,
        alias="MaintenanceActivityType",
        description="Maintenance activity type, e.g. inspection, repair, preventive maintenance - system specific, used for reporting.",
    )
    planner_group: str | None = Field(
        default=None,
        alias="MaintenancePlannerGroup",
        description="Planner group - the team that plans the maintenance work.",
    )
    notification: str | None = Field(
        default=None,
        alias="MaintenanceNotification",
        description="Maintenance notification (malfunction report or maintenance request) the order belongs to; see get_maintenance_notification().",
    )
    basic_start_datetime: ODataDateTime = Field(
        default=None, alias="MaintOrdBasicStartDateTime", description="Basic start date and time of the order."
    )
    basic_end_datetime: ODataDateTime = Field(
        default=None, alias="MaintOrdBasicEndDateTime", description="Basic end date and time of the order."
    )
    creation_datetime: ODataDateTime = Field(
        default=None, alias="MaintOrderCreationDateTime", description="Timestamp of the creation of the order."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    system_status: str | None = Field(
        default=None,
        alias="SystemStatusText",
        description="Active system statuses as text (abbreviations), e.g. 'CRTD' (created), 'REL' (released), 'TECO'.",
    )
    user_status: str | None = Field(
        default=None,
        alias="UserStatusText",
        description="User status(es) of the record (status set by the customer-specific status profile).",
    )
    scheduled_start_datetime: ODataDateTime = Field(
        default=None,
        alias="MaintOrdSchedldBscStrtDateTime",
        description="Scheduled start (result of the order scheduling), timezone-aware.",
    )
    scheduled_end_datetime: ODataDateTime = Field(
        default=None,
        alias="MaintOrdSchedldBscEndDateTime",
        description="Scheduled end (result of the order scheduling), timezone-aware.",
    )
    reference_datetime: ODataDateTime = Field(
        default=None,
        alias="MaintOrderReferenceDateTime",
        description="Reference date and time of the order (e.g. for the calculation of the dates), timezone-aware.",
    )
    main_work_completed_datetime: ODataDateTime = Field(
        default=None,
        alias="MainWorkCompletedDateTime",
        description="Date and time when the main work of the order was completed, timezone-aware.",
    )
    latest_acceptable_completion_date: ODataDate = Field(
        default=None,
        alias="LatestAcceptableCompletionDate",
        description="Final due date - the latest acceptable date to complete the order.",
    )
    technical_object_label: str | None = Field(
        default=None,
        alias="TechnicalObjectLabel",
        description="Label of the technical object (equipment number or functional location label) as shown in the SAP UI.",
    )
    maintenance_plan: str | None = Field(
        default=None,
        alias="MaintenancePlan",
        description="Maintenance plan that generated the order (preventive maintenance); see get_maintenance_plan().",
    )
    operations: Annotated[
        list[SAPMaintenanceOrderOperationResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_MaintenanceOrderOperation",
        description="Operations of the order. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPMaintenanceOrderQueryModel(SAPODataQueryModel):
    """Search criteria for SAP maintenance orders (API_MAINTENANCEORDER)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "order_id": "MaintenanceOrder {direction}",
        "created": "MaintOrderCreationDateTime {direction}",
        "basic_start": "MaintOrdBasicStartDateTime {direction}",
    }
    EXPAND: ClassVar[str] = "to_MaintenanceOrderOperation"
    sort_by: Literal["order_id", "created", "basic_start"] = Field(default="order_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    order_ids: Annotated[list[SAPCode] | None, ODataCondition("MaintenanceOrder")] = Field(
        default=None, description="Maintenance order numbers, e.g. ['4000340']."
    )
    order_types: Annotated[list[SAPCode] | None, ODataCondition("MaintenanceOrderType")] = Field(
        default=None, description="Order types, e.g. ['PM01']. System specific."
    )
    planning_plant: Annotated[SAPCode | None, ODataCondition("MaintenancePlanningPlant")] = Field(
        default=None, description="Maintenance planning plant, e.g. '1010'."
    )
    main_work_center: Annotated[SAPCode | None, ODataCondition("MainWorkCenter")] = Field(
        default=None, description="Main work center responsible for the order."
    )
    equipment: Annotated[SAPCode | None, ODataCondition("Equipment")] = Field(
        default=None, description="Equipment the order refers to."
    )
    functional_location: Annotated[str | None, ODataCondition("FunctionalLocation")] = Field(
        default=None, description="Internal functional location ID the order refers to."
    )
    notification: Annotated[SAPCode | None, ODataCondition("MaintenanceNotification")] = Field(
        default=None, description="Maintenance notification the order was created from."
    )
    priorities: Annotated[list[SAPCode] | None, ODataCondition("MaintPriority")] = Field(
        default=None, description="Priorities, e.g. ['1'] for very high. System specific."
    )
    activity_types: Annotated[list[SAPCode] | None, ODataCondition("MaintenanceActivityType")] = Field(
        default=None, description="Maintenance activity types. System specific."
    )
    description_contains: Annotated[str | None, ODataCondition("MaintenanceOrderDesc", operator="contains")] = Field(
        default=None, description="Text contained in the order description (case-sensitive)."
    )
    created_by: Annotated[SAPCode | None, ODataCondition("CreatedByUser")] = Field(
        default=None, description="SAP user who created the order."
    )
    created_from: Annotated[
        date | None, ODataCondition("MaintOrderCreationDateTime", operator="ge", kind="timestamp")
    ] = Field(default=None, description="Only orders created on or after this date.")
    created_to: Annotated[
        date | None, ODataCondition("MaintOrderCreationDateTime", operator="le", kind="timestamp")
    ] = Field(default=None, description="Only orders created on or before this date.")
    basic_start_from: Annotated[
        date | None, ODataCondition("MaintOrdBasicStartDateTime", operator="ge", kind="timestamp")
    ] = Field(default=None, description="Only orders with basic start on or after this date.")
    basic_start_to: Annotated[
        date | None, ODataCondition("MaintOrdBasicStartDateTime", operator="le", kind="timestamp")
    ] = Field(default=None, description="Only orders with basic start on or before this date.")
    expand_items: bool = Field(default=False, description="Also return the operations of each order.")


# ---------------------------------------------------------------------------
# Maintenance notifications (API_MAINTNOTIFICATION, OData V2)
# ---------------------------------------------------------------------------


class SAPMaintenanceNotificationItemModel(SAPODataCreateModel):
    """An item (damage / object part) of an SAP maintenance notification (API_MAINTNOTIFICATION)."""

    item: Numc4 = Field(
        default="1",
        alias="MaintenanceNotificationItem",
        description="Item number (4 digits, padded), e.g. 1 -> '0001'. Unique within the notification.",
    )
    text: str | None = Field(
        default=None,
        alias="MaintNotifItemText",
        description="Short text of the item, e.g. 'Seal worn out'.",
        max_length=40,
    )
    damage_code_group: SAPCode | None = Field(
        default=None,
        alias="MaintNotifDamageCodeGroup",
        description="Code group of the damage code (catalog C, max. 8 characters) - system specific; copy from an existing document if unsure.",
        max_length=8,
    )
    damage_code: SAPCode | None = Field(
        default=None,
        alias="MaintNotificationDamageCode",
        description="Damage code within `damage_code_group` - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    object_part_code_group: SAPCode | None = Field(
        default=None,
        alias="MaintNotifObjPrtCodeGroup",
        description="Code group of the object part code (catalog B, max. 8 characters) - system specific; copy from an existing document if unsure.",
        max_length=8,
    )
    object_part_code: SAPCode | None = Field(
        default=None,
        alias="MaintNotifObjPrtCode",
        description="Object part code within `object_part_code_group` - system specific; copy from an existing document if unsure.",
        max_length=4,
    )


class SAPMaintenanceNotificationModel(SAPODataCreateModel):
    """Data to create an SAP maintenance notification (API_MAINTNOTIFICATION, OData V2).

    The affected object is given as technical object plus its type ("EAMS_EQUI" for
    an equipment, "EAMS_FL" for a functional location) - the API has no separate
    equipment field. The notification number is assigned by SAP.

    See: https://api.sap.com/api/API_MAINTNOTIFICATION/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "NotificationType": "M2",
                    "NotificationText": "Pump is leaking",
                    "MaintPriority": "2",
                    "TechnicalObject": "210100001",
                    "TechObjIsEquipOrFuncnlLoc": "EAMS_EQUI",
                    "MaintenanceObjectIsDown": True,
                    "MalfunctionStartDate": "2026-11-01",
                    "MalfunctionStartTime": "07:45:00",
                }
            ]
        }
    )

    notification_type: SAPCode = Field(
        alias="NotificationType",
        description="Notification type, e.g. 'M1' (maintenance request), 'M2' (malfunction report) - system specific; copy from an existing document if unsure.",
        min_length=1,
        max_length=2,
    )
    text: str = Field(
        alias="NotificationText",
        description="Short text describing the problem, e.g. 'Pump is leaking'.",
        min_length=1,
        max_length=40,
    )
    long_text: str | None = Field(
        default=None,
        alias="MaintNotifLongTextForEdit",
        description="Long text with a detailed description of the problem (unlimited length).",
    )
    priority: SAPCode | None = Field(
        default=None,
        alias="MaintPriority",
        description="Maintenance priority, e.g. '1' (very high) to '4' (low) - system specific; copy from an existing document if unsure.",
        max_length=1,
    )
    technical_object: SAPCode | None = Field(
        default=None,
        alias="TechnicalObject",
        description="Affected equipment number or functional location label, e.g. '210100001'. Requires `technical_object_type`.",
        max_length=40,
    )
    technical_object_type: Literal["EAMS_EQUI", "EAMS_FL"] | None = Field(
        default=None,
        alias="TechObjIsEquipOrFuncnlLoc",
        description="Type of `technical_object`: 'EAMS_EQUI' (equipment) or 'EAMS_FL' (functional location). Required if `technical_object` is given.",
    )
    planning_plant: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant, e.g. '1010'. Usually derived from the technical object.",
        max_length=4,
    )
    planner_group: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlannerGroup",
        description="Maintenance planner group, e.g. '010' - system specific; copy from an existing document if unsure.",
        max_length=3,
    )
    main_work_center: SAPCode | None = Field(
        default=None,
        alias="MainWorkCenter",
        description="Main work center responsible, e.g. 'RES-0100'. Usually derived from the technical object.",
        max_length=8,
    )
    main_work_center_plant: SAPCode | None = Field(
        default=None,
        alias="MainWorkCenterPlant",
        description="Plant of the main work center, e.g. '1010'.",
        max_length=4,
    )
    reported_by: SAPCode | None = Field(
        default=None,
        alias="ReportedByUser",
        description="Name or SAP user ID of the person who reported the problem.",
        max_length=12,
    )
    breakdown: SAPFlagV2 = Field(
        default=None,
        alias="MaintenanceObjectIsDown",
        description="True if the technical object is down (breakdown), false otherwise.",
    )
    code_group: SAPCode | None = Field(
        default=None,
        alias="MaintNotificationCodeGroup",
        description="Code group of the coding (problem category, max. 8 characters) - system specific; copy from an existing document if unsure.",
        max_length=8,
    )
    code: SAPCode | None = Field(
        default=None,
        alias="MaintNotificationCode",
        description="Coding code within `code_group` - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    external_reference: str | None = Field(
        default=None,
        alias="MaintNotifExtReferenceNumber",
        description="External reference number, e.g. a ticket number of another system.",
        max_length=20,
    )
    malfunction_start_date: ODataV2Date = Field(
        default=None,
        alias="MalfunctionStartDate",
        description="Start date of the malfunction, e.g. '2026-11-01'.",
    )
    malfunction_start_time: ODataV2Time = Field(
        default=None,
        alias="MalfunctionStartTime",
        description="Start time of the malfunction, Time (HH:MM:SS), e.g. '08:30:00'.",
    )
    required_start_date: ODataV2Date = Field(
        default=None,
        alias="RequiredStartDate",
        description="Date by which work should start, e.g. '2026-11-01'.",
    )
    required_end_date: ODataV2Date = Field(
        default=None,
        alias="RequiredEndDate",
        description="Date by which work should be finished, e.g. '2026-11-01'. Must not be before `required_start_date`.",
    )
    # The navigation property name follows the RAP OData V2 convention (association _Item -> to_Item):
    items: Annotated[list[SAPMaintenanceNotificationItemModel], unique_numbers("item")] = Field(
        default_factory=list,
        alias="to_Item",
        description="Items (damages / object parts) of the notification. Item numbers must be unique.",
        exclude_if=is_empty,
    )

    @model_validator(mode="after")
    def check_consistency(self) -> Self:
        """Validate dependencies between fields."""

        if self.technical_object and not self.technical_object_type:
            message = "Technical object -> '{}' needs a technical object type ('EAMS_EQUI' or 'EAMS_FL')".format(
                self.technical_object,
            )
            raise ValueError(message)

        if self.required_start_date and self.required_end_date and self.required_end_date < self.required_start_date:
            message = "Required end date -> {} is before required start date -> {}".format(
                self.required_end_date,
                self.required_start_date,
            )
            raise ValueError(message)

        return self

    # end method definition


class SAPMaintenanceNotificationItemResponseModel(SAPODataModel):
    """An item of an SAP maintenance notification as returned by SAP (API_MAINTNOTIFICATION)."""

    notification_id: str = Field(
        alias="MaintenanceNotification",
        description="Maintenance notification (malfunction report or maintenance request) the order belongs to; see get_maintenance_notification().",
    )
    item: str = Field(alias="MaintenanceNotificationItem", description="Item number (4 digits), e.g. '0001'.")
    text: str | None = Field(default=None, alias="MaintNotifItemText", description="Short text of the item.")
    damage_code_group: str | None = Field(
        default=None, alias="MaintNotifDamageCodeGroup", description="Code group of the damage code."
    )
    damage_code: str | None = Field(default=None, alias="MaintNotificationDamageCode", description="Damage code.")
    object_part_code_group: str | None = Field(
        default=None, alias="MaintNotifObjPrtCodeGroup", description="Code group of the object part code."
    )
    object_part_code: str | None = Field(default=None, alias="MaintNotifObjPrtCode", description="Object part code.")
    is_deleted: SAPFlag = Field(default=None, alias="IsDeleted", description="True if the item has been deleted.")


class SAPMaintenanceNotificationResponseModel(SAPODataModel):
    """An SAP maintenance notification as returned by SAP (API_MAINTNOTIFICATION).

    All fields except the notification number are optional and timestamps are
    converted into timezone-aware datetime objects.

    Attributes:
        items (list[SAPMaintenanceNotificationItemResponseModel] | None):
            The items of the notification. None if the items have not been
            requested ($expand), an empty list if the notification has no items.

    """

    notification_id: str = Field(
        alias="MaintenanceNotification",
        description="Maintenance notification (malfunction report or maintenance request) the order belongs to; see get_maintenance_notification().",
    )
    notification_type: str | None = Field(
        default=None,
        alias="NotificationType",
        description="Notification type, e.g. 'M1' (maintenance request), 'M2' (malfunction report) - system specific.",
    )
    text: str | None = Field(default=None, alias="NotificationText", description="Short text describing the problem.")
    long_text: str | None = Field(
        default=None,
        alias="MaintNotificationLongText",
        description="Long text with a detailed description of the problem.",
    )
    priority: str | None = Field(
        default=None,
        alias="MaintPriority",
        description="Priority, e.g. '1' (very high) to '4' (low) - system specific.",
    )
    technical_object: str | None = Field(
        default=None, alias="TechnicalObject", description="Affected equipment number or functional location."
    )
    technical_object_type: str | None = Field(
        default=None,
        alias="TechObjIsEquipOrFuncnlLoc",
        description="Type of the technical object: 'EAMS_EQUI' (equipment) or 'EAMS_FL' (functional location).",
    )
    technical_object_label: str | None = Field(
        default=None,
        alias="TechnicalObjectLabel",
        description="Label of the technical object (equipment number or functional location label) as shown in the SAP UI.",
    )
    functional_location: str | None = Field(
        default=None,
        alias="FunctionalLocationLabelName",
        description="Functional location label as shown in the SAP UI, e.g. 'C1-B01-1'.",
    )
    planning_plant: str | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant - the plant whose planner groups plan and schedule the maintenance work.",
    )
    planner_group: str | None = Field(
        default=None,
        alias="MaintenancePlannerGroup",
        description="Planner group - the team that plans the maintenance work.",
    )
    main_work_center: str | None = Field(
        default=None,
        alias="MainWorkCenter",
        description="Main work center - responsible for executing the maintenance work; see get_work_center().",
    )
    main_work_center_plant: str | None = Field(
        default=None, alias="MainWorkCenterPlant", description="Plant of the main work center."
    )
    reported_by: str | None = Field(
        default=None, alias="ReportedByUser", description="Person who reported the problem."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    breakdown: SAPFlag = Field(
        default=None, alias="MaintenanceObjectIsDown", description="True if the technical object is down (breakdown)."
    )
    maintenance_order: str | None = Field(
        default=None,
        alias="MaintenanceOrder",
        description="Maintenance order number; see get_maintenance_order().",
    )
    system_status: str | None = Field(
        default=None,
        alias="ConcatenatedActiveSystStsName",
        description="Active system statuses as text, e.g. 'OSNO' (outstanding), 'NOPR' (in process), 'NOCO' (completed).",
    )
    processing_phase: str | None = Field(
        default=None,
        alias="NotifProcessingPhase",
        description="Processing phase code, e.g. '1' (outstanding), '3' (in process), '4' (completed).",
    )
    creation_datetime: ODataDateTime = Field(
        default=None, alias="CreationDateTime", description="Timestamp of the creation of the notification."
    )
    malfunction_start_datetime: ODataDateTime = Field(
        default=None, alias="MalfunctionStartDateTime", description="Start date and time of the malfunction."
    )
    required_start_datetime: ODataDateTime = Field(
        default=None, alias="MaintNotifRqdStartDateTime", description="Date and time by which work should start."
    )
    required_end_datetime: ODataDateTime = Field(
        default=None, alias="MaintNotifRqdEndDateTime", description="Date and time by which work should be finished."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    notification_date: ODataDate = Field(
        default=None,
        alias="NotificationCreationDate",
        description="Date of the notification (as entered, may differ from the creation timestamp).",
    )
    notification_time: ODataTime = Field(
        default=None, alias="NotificationCreationTime", description="Time of the notification."
    )
    malfunction_end_date: ODataDate = Field(
        default=None, alias="MalfunctionEndDate", description="Date when the malfunction ended (problem solved)."
    )
    malfunction_end_time: ODataTime = Field(
        default=None, alias="MalfunctionEndTime", description="Time when the malfunction ended (problem solved)."
    )
    latest_acceptable_completion_date: ODataDate = Field(
        default=None,
        alias="LatestAcceptableCompletionDate",
        description="Final due date - the latest acceptable date to complete the notification.",
    )
    reference_date: ODataDate = Field(
        default=None, alias="NotificationReferenceDate", description="Reference date of the notification."
    )
    reference_time: ODataTime = Field(
        default=None, alias="NotificationReferenceTime", description="Reference time of the notification."
    )
    completion_date: ODataDate = Field(
        default=None, alias="NotificationCompletionDate", description="Date when the notification was completed."
    )
    completion_time: ODataTime = Field(
        default=None, alias="CompletionTime", description="Time when the notification was completed."
    )
    code_group: str | None = Field(
        default=None,
        alias="MaintNotificationCodeGroup",
        description="Code group of the notification coding (catalog) - groups the codes.",
    )
    code: str | None = Field(
        default=None,
        alias="MaintNotificationCode",
        description="Code within the code group that classifies the notification (e.g. the kind of problem).",
    )
    functional_location_id: str | None = Field(
        default=None,
        alias="FunctionalLocation",
        description="Functional location (internal ID) - a place in the technical structure where equipment is installed; see get_functional_location().",
    )
    items: Annotated[
        list[SAPMaintenanceNotificationItemResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_Item",
        description="Items of the notification. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPMaintenanceNotificationQueryModel(SAPODataQueryModel):
    """Search criteria for SAP maintenance notifications (API_MAINTNOTIFICATION)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "notification_id": "MaintenanceNotification {direction}",
        "created": "CreationDateTime {direction}",
    }
    EXPAND: ClassVar[str] = "to_Item"
    sort_by: Literal["notification_id", "created"] = Field(default="notification_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    notification_ids: Annotated[list[SAPCode] | None, ODataCondition("MaintenanceNotification")] = Field(
        default=None, description="Notification numbers, e.g. ['10000212']."
    )
    notification_types: Annotated[list[SAPCode] | None, ODataCondition("NotificationType")] = Field(
        default=None, description="Notification types, e.g. ['M1']. System specific."
    )
    planning_plant: Annotated[SAPCode | None, ODataCondition("MaintenancePlanningPlant")] = Field(
        default=None, description="Maintenance planning plant, e.g. '1010'."
    )
    technical_object: Annotated[str | None, ODataCondition("TechnicalObject")] = Field(
        default=None, description="Equipment number or internal functional location ID the notification refers to."
    )
    priorities: Annotated[list[SAPCode] | None, ODataCondition("MaintPriority")] = Field(
        default=None, description="Priorities, e.g. ['1'] for very high. System specific."
    )
    text_contains: Annotated[str | None, ODataCondition("NotificationText", operator="contains")] = Field(
        default=None, description="Text contained in the notification short text (case-sensitive)."
    )
    reported_by: Annotated[SAPCode | None, ODataCondition("ReportedByUser")] = Field(
        default=None, description="SAP user who reported the notification."
    )
    maintenance_order: Annotated[SAPCode | None, ODataCondition("MaintenanceOrder")] = Field(
        default=None, description="Maintenance order created for the notification."
    )
    processing_phases: Annotated[list[SAPCode] | None, ODataCondition("NotifProcessingPhase")] = Field(
        default=None,
        description="Processing phases: '1' outstanding, '2' postponed, '3' in process, '4' completed, '5' deletion flag.",
    )
    created_from: Annotated[date | None, ODataCondition("CreationDateTime", operator="ge", kind="timestamp")] = Field(
        default=None, description="Only notifications created on or after this date."
    )
    created_to: Annotated[date | None, ODataCondition("CreationDateTime", operator="le", kind="timestamp")] = Field(
        default=None, description="Only notifications created on or before this date."
    )
    expand_items: bool = Field(default=False, description="Also return the items (damages) of each notification.")


# ---------------------------------------------------------------------------
# Purchase orders (API_PURCHASEORDER_2, OData V4)
# ---------------------------------------------------------------------------


class SAPPurchaseOrderScheduleLineModel(SAPODataCreateModel):
    """A schedule line (delivery date and quantity) of a purchase order item (API_PURCHASEORDER_2)."""

    schedule_line: Numc4 = Field(
        default="1",
        alias="ScheduleLine",
        description="Schedule line number (4 digits, padded), e.g. 1 -> '0001'. Unique within the item.",
    )
    delivery_date: date = Field(
        alias="ScheduleLineDeliveryDate", description="Requested delivery date, e.g. '2026-11-01'."
    )
    quantity: SAPDecimal | None = Field(
        default=None,
        alias="ScheduleLineOrderQuantity",
        description="Quantity to deliver on this date (in the order unit). Defaults to the item quantity.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )


class SAPPurchaseOrderAccountAssignmentModel(SAPODataCreateModel):
    """An account assignment of a purchase order item (API_PURCHASEORDER_2).

    Required if the item has an account assignment category, e.g. "K" (cost center)
    requires a cost center and a G/L account.

    """

    number: Numc2 = Field(
        default="1",
        alias="AccountAssignmentNumber",
        description="Account assignment number (2 digits, padded), e.g. 1 -> '01'. Unique within the item.",
    )
    cost_center: SAPCode | None = Field(
        default=None,
        alias="CostCenter",
        description="Cost center to charge, e.g. '10101101'. Required for account assignment category 'K'.",
        max_length=10,
    )
    gl_account: SAPCode | None = Field(
        default=None,
        alias="GLAccount",
        description="G/L account to post to, e.g. '61003000'. Usually required for cost center assignments.",
        max_length=10,
    )
    internal_order: SAPCode | None = Field(
        default=None,
        alias="OrderID",
        description="Internal order (CO order) to charge. Used with account assignment category 'F'.",
        max_length=12,
    )
    wbs_element: SAPCode | None = Field(
        default=None,
        alias="WBSElementExternalID",
        description="WBS element (project) to charge, external ID. Used with account assignment category 'P'.",
        max_length=24,
    )
    quantity: SAPDecimal | None = Field(
        default=None,
        alias="Quantity",
        description="Quantity assigned to this account (for multiple account assignment).",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    distribution_percent: SAPDecimal | None = Field(
        default=None,
        alias="MultipleAcctAssgmtDistrPercent",
        description="Percentage of the item assigned to this account (0-100, for multiple account assignment).",
        gt=0,
        le=100,
        decimal_places=1,
    )


class SAPPurchaseOrderItemModel(SAPPurchasingItemModel):
    """An item of a purchase order (API_PURCHASEORDER_2).

    An item needs either a material or a short text plus a material group.
    Items can only be created together with the purchase order (SAP does not
    allow adding items to an existing purchase order via this API).

    """

    item: Numc5 = Field(
        default="10",
        alias="PurchaseOrderItem",
        description="Item number (5 digits, padded), e.g. 10 -> '00010'. Unique within the purchase order.",
    )
    text: str | None = Field(
        default=None,
        alias="PurchaseOrderItemText",
        description="Short text of the item. Required if no `material` is given; then `material_group` is required too.",
        max_length=40,
    )
    plant: SAPCode | None = Field(
        default=None, alias="Plant", description="Receiving plant, e.g. '1010'.", max_length=4
    )
    storage_location: SAPCode | None = Field(
        default=None,
        alias="StorageLocation",
        description="Receiving storage location, e.g. '101A'.",
        max_length=4,
    )
    quantity: SAPDecimal = Field(
        alias="OrderQuantity",
        description="Order quantity (greater than 0), e.g. 20.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="PurchaseOrderQuantityUnit",
        description="Order unit as stored in SAP (internal unit code, max. 3 characters), e.g. 'ST' (piece). Defaults to the order unit of the material.",
        max_length=3,
    )
    net_price: SAPDecimal | None = Field(
        default=None,
        alias="NetPriceAmount",
        description="Net price per `price_unit` in the document currency, e.g. 32.00. Defaults to the price from purchasing info records.",
        ge=0,
        max_digits=11,
        decimal_places=2,
    )
    price_unit: SAPDecimal | None = Field(
        default=None,
        alias="NetPriceQuantity",
        description="Quantity the net price refers to, e.g. 100 for a price per 100 pieces. Defaults to 1.",
        gt=0,
        max_digits=5,
        decimal_places=0,
    )
    item_category: SAPCode | None = Field(
        default=None,
        alias="PurchaseOrderItemCategory",
        description="Item category: empty = standard, 'K' consignment, 'L' subcontracting, 'D' service, 'S' third-party - system specific; copy from an existing document if unsure.",
        max_length=1,
    )
    tax_code: SAPCode | None = Field(
        default=None,
        alias="TaxCode",
        description="Tax code (country specific), e.g. 'V1' - system specific; copy from an existing document if unsure.",
        max_length=2,
    )
    requisitioner: str | None = Field(
        default=None,
        alias="RequisitionerName",
        description="Name of the requisitioner (free text, max. 12 characters).",
        max_length=12,
    )
    schedule_lines: Annotated[list[SAPPurchaseOrderScheduleLineModel], unique_numbers("schedule_line")] = Field(
        default_factory=list,
        alias="_PurchaseOrderScheduleLineTP",
        description="Delivery schedule (dates and quantities). Schedule line numbers must be unique within the item.",
        exclude_if=is_empty,
    )
    account_assignments: Annotated[list[SAPPurchaseOrderAccountAssignmentModel], unique_numbers("number")] = Field(
        default_factory=list,
        alias="_PurOrdAccountAssignment",
        description="Account assignments (who pays). Require `account_assignment_category`. Numbers must be unique within the item.",
        exclude_if=is_empty,
    )


class SAPPurchaseOrderModel(SAPODataCreateModel):
    """Data to create an SAP purchase order (API_PURCHASEORDER_2, OData V4).

    The purchase order number is assigned by SAP. Which further fields are
    required depends on the customizing (order type, supplier, material).

    See: https://help.sap.com/docs/SAP_S4HANA_ON-PREMISE/f296651f454c4284ade361292c633d69/dbf882e32bac456eb506bc415f0d2df1.html

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "CompanyCode": "3000",
                    "PurchasingOrganization": "3000",
                    "PurchasingGroup": "001",
                    "Supplier": "30050",
                    "_PurchaseOrderItem": [
                        {
                            "Material": "R-9010",
                            "Plant": "3000",
                            "OrderQuantity": 20,
                            "NetPriceAmount": 32.0,
                            "AccountAssignmentCategory": "K",
                            "_PurchaseOrderScheduleLineTP": [{"ScheduleLineDeliveryDate": "2026-11-01"}],
                            "_PurOrdAccountAssignment": [{"CostCenter": "4130", "GLAccount": "400000"}],
                        }
                    ],
                }
            ]
        }
    )

    order_type: SAPCode = Field(
        default="NB",
        alias="PurchaseOrderType",
        description="Purchase order type. 'NB' (standard purchase order, default); the API supports NB and copies of it - system specific; copy from an existing document if unsure.",
        min_length=1,
        max_length=4,
    )
    company_code: SAPCode = Field(
        alias="CompanyCode",
        description="Company code of the ordering legal entity, e.g. '1010'.",
        min_length=1,
        max_length=4,
    )
    purchasing_organization: SAPCode = Field(
        alias="PurchasingOrganization",
        description="Purchasing organization, e.g. '1010'.",
        min_length=1,
        max_length=4,
    )
    purchasing_group: SAPCode = Field(
        alias="PurchasingGroup",
        description="Purchasing group (the responsible buyer or buyer team), e.g. '001'.",
        min_length=1,
        max_length=3,
    )
    supplier: SAPCode = Field(
        alias="Supplier",
        description="Supplier number (business partner, max. 10 characters), e.g. '10300001'.",
        min_length=1,
        max_length=10,
    )
    currency: SAPCode | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO code), e.g. 'EUR'. Defaults to the currency of the supplier.",
        max_length=5,
    )
    order_date: date | None = Field(
        default=None,
        alias="PurchaseOrderDate",
        description="Purchase order date, e.g. '2026-11-01'. Defaults to today.",
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="PaymentTerms",
        description="Terms of payment key, e.g. '0001'. Defaults to the supplier's terms - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    your_reference: str | None = Field(
        default=None,
        alias="CorrespncExternalReference",
        description="External reference, e.g. the supplier's quotation number.",
        max_length=12,
    )
    items: Annotated[list[SAPPurchaseOrderItemModel], unique_numbers("item")] = Field(
        alias="_PurchaseOrderItem",
        description="Items of the purchase order (at least one). Item numbers must be unique.",
        min_length=1,
    )


class SAPPurchaseOrderScheduleLineResponseModel(SAPODataModel):
    """A schedule line of a purchase order item as returned by SAP (API_PURCHASEORDER_2)."""

    order_id: str = Field(alias="PurchaseOrder", description="Purchase order number.")
    item: str = Field(alias="PurchaseOrderItem", description="Purchase order item number (5 digits), e.g. '00010'.")
    schedule_line: str = Field(alias="ScheduleLine", description="Schedule line number (4 digits), e.g. '0001'.")
    delivery_date: date | None = Field(
        default=None, alias="ScheduleLineDeliveryDate", description="Delivery date of the schedule line."
    )
    quantity: SAPDecimal | None = Field(
        default=None, alias="ScheduleLineOrderQuantity", description="Quantity scheduled for delivery on this date."
    )
    unit: str | None = Field(
        default=None, alias="PurchaseOrderQuantityUnit", description="Order unit (internal SAP unit code), e.g. 'ST'."
    )
    delivery_time: ODataTime = Field(
        default=None,
        alias="ScheduleLineDeliveryTime",
        description="Delivery time on the delivery date of the schedule line.",
    )
    statistical_delivery_date: ODataDate = Field(
        default=None,
        alias="SchedLineStscDeliveryDate",
        description="Statistics-relevant (originally agreed) delivery date - used to evaluate supplier delivery performance.",
    )
    performance_period_start_date: ODataDate = Field(
        default=None,
        alias="PerformancePeriodStartDate",
        description="Start of the period of performance (for services).",
    )
    performance_period_end_date: ODataDate = Field(
        default=None, alias="PerformancePeriodEndDate", description="End of the period of performance (for services)."
    )
    open_quantity: SAPDecimal | None = Field(
        default=None,
        alias="OpenPurchaseOrderQuantity",
        description="Quantity of the schedule line that is still to be delivered (ordered quantity minus goods receipts).",
    )


class SAPPurchaseOrderAccountAssignmentResponseModel(SAPODataModel):
    """An account assignment of a purchase order item as returned by SAP (API_PURCHASEORDER_2)."""

    order_id: str = Field(alias="PurchaseOrder", description="Purchase order number.")
    item: str = Field(alias="PurchaseOrderItem", description="Purchase order item number (5 digits), e.g. '00010'.")
    number: str = Field(alias="AccountAssignmentNumber", description="Account assignment number (2 digits), e.g. '01'.")
    cost_center: str | None = Field(
        default=None,
        alias="CostCenter",
        description="Cost center that is charged with the costs; see get_cost_center().",
    )
    gl_account: str | None = Field(
        default=None, alias="GLAccount", description="G/L account the values are posted to; see get_gl_account()."
    )
    internal_order: str | None = Field(
        default=None, alias="OrderID", description="Internal order (CO order) that is charged with the costs."
    )
    wbs_element: str | None = Field(
        default=None,
        alias="WBSElementExternalID",
        description="WBS element (element of a project structure) that is charged with the costs.",
    )
    controlling_area: str | None = Field(
        default=None,
        alias="ControllingArea",
        description="Controlling area - the organizational unit of cost accounting that cost and profit centers belong to.",
    )
    quantity: SAPDecimal | None = Field(
        default=None, alias="Quantity", description="Quantity assigned to this account."
    )
    distribution_percent: SAPDecimal | None = Field(
        default=None,
        alias="MultipleAcctAssgmtDistrPercent",
        description="Percentage of the item assigned to this account.",
    )
    settlement_reference_date: ODataDate = Field(
        default=None,
        alias="SettlementReferenceDate",
        description="Reference date for the settlement of the account assignment.",
    )


class SAPPurchaseOrderItemResponseModel(SAPODataModel):
    """An item of a purchase order as returned by SAP (API_PURCHASEORDER_2).

    Attributes:
        schedule_lines / account_assignments:
            None if they have not been requested ($expand), otherwise a (possibly empty) list.

    """

    order_id: str = Field(alias="PurchaseOrder", description="Purchase order number.")
    item: str = Field(alias="PurchaseOrderItem", description="Item number (5 digits), e.g. '00010'.")
    text: str | None = Field(default=None, alias="PurchaseOrderItemText", description="Short text of the item.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    material_group: str | None = Field(
        default=None,
        alias="MaterialGroup",
        description="Material group - classifies materials and services; used for items without material number (e.g. services).",
    )
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    storage_location: str | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location within the plant where the material is stored; see get_storage_locations().",
    )
    quantity: SAPDecimal | None = Field(default=None, alias="OrderQuantity", description="Order quantity.")
    unit: str | None = Field(
        default=None, alias="PurchaseOrderQuantityUnit", description="Order unit (internal SAP unit code), e.g. 'ST'."
    )
    net_price: SAPDecimal | None = Field(
        default=None, alias="NetPriceAmount", description="Net price per `price_unit` in the document currency."
    )
    price_unit: SAPDecimal | None = Field(
        default=None,
        alias="NetPriceQuantity",
        description="Quantity the net price refers to (e.g. 100 for a price per 100 pieces).",
    )
    net_amount: SAPDecimal | None = Field(
        default=None, alias="NetAmount", description="Net value of the item in the document currency."
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    account_assignment_category: str | None = Field(
        default=None,
        alias="AccountAssignmentCategory",
        description="Account assignment category - what the item is charged to: 'K' cost center, 'F' internal order, 'P' project, empty for stock.",
    )
    item_category: str | None = Field(
        default=None,
        alias="PurchaseOrderItemCategory",
        description="Item category, e.g. empty (standard), 'K' (consignment), 'L' (subcontracting).",
    )
    tax_code: str | None = Field(
        default=None, alias="TaxCode", description="Tax code - determines the tax rate and tax account."
    )
    requisitioner: str | None = Field(default=None, alias="RequisitionerName", description="Name of the requisitioner.")
    deletion_code: str | None = Field(
        default=None,
        alias="PurchasingDocumentDeletionCode",
        description="Deletion indicator: 'L' = deleted, 'S' = blocked, empty = active.",
    )
    purchase_requisition: str | None = Field(
        default=None,
        alias="PurchaseRequisition",
        description="Purchase requisition (internal request) the item was created from; see get_purchase_requisition().",
    )
    purchase_requisition_item: str | None = Field(
        default=None,
        alias="PurchaseRequisitionItem",
        description="Item of the purchase requisition the item was created from.",
    )
    purchase_contract: str | None = Field(
        default=None,
        alias="PurchaseContract",
        description="Purchase contract (outline agreement) the item is ordered against; see get_purchase_contract().",
    )
    purchase_contract_item: str | None = Field(
        default=None,
        alias="PurchaseContractItem",
        description="Item of the purchase contract the item is ordered against.",
    )
    goods_receipt_expected: SAPFlag = Field(
        default=None,
        alias="GoodsReceiptIsExpected",
        description="True if a goods receipt is expected for the item (prerequisite for posting one, see create_goods_movement()).",
    )
    is_completely_delivered: SAPFlag = Field(
        default=None,
        alias="IsCompletelyDelivered",
        description="True if the item is completely delivered - no further goods receipts are expected.",
    )
    schedule_lines: list[SAPPurchaseOrderScheduleLineResponseModel] | None = Field(
        default=None,
        alias="_PurchaseOrderScheduleLineTP",
        description="Schedule lines. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    account_assignments: list[SAPPurchaseOrderAccountAssignmentResponseModel] | None = Field(
        default=None,
        alias="_PurOrdAccountAssignment",
        description="Account assignments. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    down_payment_due_date: ODataDate = Field(
        default=None, alias="DownPaymentDueDate", description="Due date of the down payment for the item."
    )
    tax_determination_date: ODataDate = Field(
        default=None, alias="TaxDeterminationDate", description="Date used to determine the tax (rate) of the item."
    )


class SAPPurchaseOrderResponseModel(SAPODataModel):
    """A purchase order as returned by SAP (API_PURCHASEORDER_2, OData V4).

    All fields except the purchase order number are optional.

    Attributes:
        items (list[SAPPurchaseOrderItemResponseModel] | None):
            The items of the purchase order. None if they have not been requested
            ($expand), otherwise a (possibly empty) list.

    """

    order_id: str = Field(
        alias="PurchaseOrder", description="Purchase order number (assigned by SAP), e.g. '4500000001'."
    )
    order_type: str | None = Field(
        default=None, alias="PurchaseOrderType", description="Purchase order type, e.g. 'NB' (standard)."
    )
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    purchasing_organization: str | None = Field(
        default=None,
        alias="PurchasingOrganization",
        description="Purchasing organization - negotiates the conditions with suppliers; see get_purchasing_organizations().",
    )
    purchasing_group: str | None = Field(
        default=None,
        alias="PurchasingGroup",
        description="Purchasing group - the buyer or group of buyers responsible for the document.",
    )
    supplier: str | None = Field(
        default=None,
        alias="Supplier",
        description="Supplier (vendor) number - a business partner in the supplier role; see get_vendors().",
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    order_date: date | None = Field(default=None, alias="PurchaseOrderDate", description="Purchase order date.")
    creation_date: date | None = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    processing_status: str | None = Field(
        default=None,
        alias="PurchasingProcessingStatus",
        description="Processing status, e.g. '01' (in process), '02' (active), '05' (released), '08' (rejected).",
    )
    deletion_code: str | None = Field(
        default=None,
        alias="PurchaseOrderDeletionCode",
        description="Deletion indicator: 'L' = deleted, empty = active.",
    )
    payment_terms: str | None = Field(
        default=None,
        alias="PaymentTerms",
        description="Terms of payment key, e.g. '0001' (payable immediately) - system specific.",
    )
    your_reference: str | None = Field(
        default=None,
        alias="CorrespncExternalReference",
        description="Reference of the business partner (e.g. the supplier's quotation or the customer's reference).",
    )
    items: list[SAPPurchaseOrderItemResponseModel] | None = Field(
        default=None,
        alias="_PurchaseOrderItem",
        description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )

    # ---------------------------------------------------------------------------
    # Sales orders (API_SALES_ORDER_SRV, OData V2)
    # ---------------------------------------------------------------------------
    validity_start_date: ODataDate = Field(
        default=None, alias="ValidityStartDate", description="Start of the validity period of the purchase order."
    )
    validity_end_date: ODataDate = Field(
        default=None, alias="ValidityEndDate", description="End of the validity period of the purchase order."
    )


class SAPPurchaseOrderQueryModel(SAPODataQueryModel):
    """Search criteria for SAP purchase orders (API_PURCHASEORDER_2, OData V4)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "order_id": "PurchaseOrder {direction}",
        "order_date": "PurchaseOrderDate {direction}",
    }
    EXPAND: ClassVar[str] = "_PurchaseOrderItem($expand=_PurchaseOrderScheduleLineTP,_PurOrdAccountAssignment)"
    sort_by: Literal["order_id", "order_date"] = Field(default="order_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    order_ids: Annotated[list[SAPCode] | None, ODataCondition("PurchaseOrder")] = Field(
        default=None, description="Purchase order numbers, e.g. ['4500000123']."
    )
    order_types: Annotated[list[SAPCode] | None, ODataCondition("PurchaseOrderType")] = Field(
        default=None, description="Purchase order types, e.g. ['NB']. System specific."
    )
    supplier: Annotated[SAPCode | None, ODataCondition("Supplier")] = Field(
        default=None, description="Supplier (vendor) number."
    )
    company_code: Annotated[SAPCode | None, ODataCondition("CompanyCode")] = Field(
        default=None, description="Company code, e.g. '1010'."
    )
    purchasing_organization: Annotated[SAPCode | None, ODataCondition("PurchasingOrganization")] = Field(
        default=None, description="Purchasing organization, e.g. '1010'."
    )
    purchasing_group: Annotated[SAPCode | None, ODataCondition("PurchasingGroup")] = Field(
        default=None, description="Purchasing group (buyer), e.g. '001'."
    )
    created_by: Annotated[SAPCode | None, ODataCondition("CreatedByUser")] = Field(
        default=None, description="SAP user who created the purchase order."
    )
    order_date_from: Annotated[date | None, ODataCondition("PurchaseOrderDate", operator="ge")] = Field(
        default=None, description="Only purchase orders dated on or after this date."
    )
    order_date_to: Annotated[date | None, ODataCondition("PurchaseOrderDate", operator="le")] = Field(
        default=None, description="Only purchase orders dated on or before this date."
    )
    material: Annotated[SAPCode | None, ODataCondition("Material", path="_PurchaseOrderItem")] = Field(
        default=None, description="Only purchase orders with an item for this material."
    )
    plant: Annotated[SAPCode | None, ODataCondition("Plant", path="_PurchaseOrderItem")] = Field(
        default=None, description="Only purchase orders with an item for this plant."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each purchase order.")


class SAPSalesOrderItemModel(SAPODataCreateModel):
    """An item of an SAP sales order (API_SALES_ORDER_SRV)."""

    item: Numc6 = Field(
        default="10",
        alias="SalesOrderItem",
        description="Item number (6 digits, padded), e.g. 10 -> '000010'. Unique within the sales order.",
    )
    material: SAPCode = Field(
        alias="Material",
        description="Material (product) number to sell, e.g. 'TG11'.",
        min_length=1,
        max_length=40,
    )
    text: str | None = Field(
        default=None,
        alias="SalesOrderItemText",
        description="Short text of the item. Defaults to the material description.",
        max_length=40,
    )
    quantity: SAPDecimal = Field(
        alias="RequestedQuantity", description="Requested quantity (greater than 0), e.g. 10.", gt=0, decimal_places=3
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="RequestedQuantityUnit",
        description="Sales unit (internal SAP unit code, max. 3 characters), e.g. 'ST' (piece). Defaults to the sales unit of the material.",
        max_length=3,
    )
    plant: SAPCode | None = Field(
        default=None,
        alias="ProductionPlant",
        description="Delivering plant, e.g. '1010'. Usually determined from customer / material master data.",
        max_length=4,
    )
    item_category: SAPCode | None = Field(
        default=None,
        alias="SalesOrderItemCategory",
        description="Sales document item category, e.g. 'TAN' (standard item). Usually determined automatically - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    customer_material: str | None = Field(
        default=None,
        alias="MaterialByCustomer",
        description="The customer's own material number.",
        max_length=35,
    )


class SAPSalesOrderModel(SAPODataCreateModel):
    """Data to create an SAP sales order (API_SALES_ORDER_SRV, OData V2).

    The sales order number is assigned by SAP. Which further fields are required
    depends on the customizing of the sales document type.

    See: https://api.sap.com/api/API_SALES_ORDER_SRV/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "SalesOrderType": "YT",
                    "SalesOrganization": "3000",
                    "DistributionChannel": "10",
                    "OrganizationDivision": "00",
                    "SoldToParty": "52001",
                    "PurchaseOrderByCustomer": "PO-4711",
                    "RequestedDeliveryDate": "2026-12-01",
                    "to_Item": [{"Material": "P-100", "RequestedQuantity": 10}],
                }
            ]
        }
    )

    order_type: SAPCode = Field(
        alias="SalesOrderType",
        description="Sales document type, e.g. 'OR' / 'TA' (standard order) or 'YT' - system specific; copy from an existing document if unsure.",
        min_length=1,
        max_length=4,
    )
    sales_organization: SAPCode = Field(
        alias="SalesOrganization",
        description="Sales organization, e.g. '1010'.",
        min_length=1,
        max_length=4,
    )
    distribution_channel: SAPCode = Field(
        alias="DistributionChannel",
        description="Distribution channel, e.g. '10' (direct sales).",
        min_length=1,
        max_length=2,
    )
    division: SAPCode = Field(
        alias="OrganizationDivision",
        description="Division, e.g. '00' (cross-division).",
        min_length=1,
        max_length=2,
    )
    sold_to_party: SAPCode = Field(
        alias="SoldToParty",
        description="Customer number of the sold-to party, e.g. '10100001'.",
        min_length=1,
        max_length=10,
    )
    sales_group: SAPCode | None = Field(
        default=None,
        alias="SalesGroup",
        description="Sales group - system specific; copy from an existing document if unsure.",
        max_length=3,
    )
    sales_office: SAPCode | None = Field(
        default=None,
        alias="SalesOffice",
        description="Sales office - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    customer_reference: str | None = Field(
        default=None,
        alias="PurchaseOrderByCustomer",
        description="The customer's purchase order number, e.g. 'PO-4711'.",
        max_length=35,
    )
    customer_reference_date: ODataV2Date = Field(
        default=None,
        alias="CustomerPurchaseOrderDate",
        description="Date of the customer's purchase order, e.g. '2026-11-01'.",
    )
    requested_delivery_date: ODataV2Date = Field(
        default=None,
        alias="RequestedDeliveryDate",
        description="Requested delivery date, e.g. '2026-11-01'.",
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="CustomerPaymentTerms",
        description="Terms of payment key, e.g. '0001'. Defaults to the customer's terms - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    currency: SAPCode | None = Field(
        default=None,
        alias="TransactionCurrency",
        description="Document currency (ISO code), e.g. 'EUR'. Defaults to the currency of the customer.",
        max_length=5,
    )
    items: Annotated[list[SAPSalesOrderItemModel], unique_numbers("item")] = Field(
        alias="to_Item",
        description="Items of the sales order (at least one). Item numbers must be unique.",
        min_length=1,
    )


class SAPSalesOrderItemResponseModel(SAPODataModel):
    """An item of an SAP sales order as returned by SAP (API_SALES_ORDER_SRV)."""

    order_id: str = Field(
        alias="SalesOrder",
        description="Sales order the record belongs to (e.g. make-to-order production); see get_sales_order().",
    )
    item: str = Field(alias="SalesOrderItem", description="Item of the sales order.")
    text: str | None = Field(default=None, alias="SalesOrderItemText", description="Short text of the item.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    quantity: SAPDecimal | None = Field(default=None, alias="RequestedQuantity", description="Requested quantity.")
    unit: str | None = Field(
        default=None, alias="RequestedQuantityUnit", description="Sales unit (internal SAP unit code)."
    )
    net_amount: SAPDecimal | None = Field(
        default=None, alias="NetAmount", description="Net value of the item in the document currency."
    )
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    plant: str | None = Field(
        default=None, alias="ProductionPlant", description="Plant in which the material is produced; see get_plants()."
    )
    item_category: str | None = Field(
        default=None, alias="SalesOrderItemCategory", description="Sales document item category, e.g. 'TAN'."
    )
    delivery_status: str | None = Field(
        default=None,
        alias="DeliveryStatus",
        description="Delivery status: 'A' not delivered, 'B' partially delivered, 'C' fully delivered.",
    )
    process_status: str | None = Field(
        default=None,
        alias="SDProcessStatus",
        description="Overall processing status: 'A' open, 'B' in process, 'C' completed.",
    )
    rejection_reason: str | None = Field(
        default=None,
        alias="SalesDocumentRjcnReason",
        description="Reason for rejection (empty if the item is not rejected).",
    )
    pricing_date: ODataDate = Field(
        default=None, alias="PricingDate", description="Date used for pricing and the exchange rate of the item."
    )
    billing_date: ODataDate = Field(default=None, alias="BillingDocumentDate", description="Billing date of the item.")
    services_rendered_date: ODataDate = Field(
        default=None, alias="ServicesRenderedDate", description="Date on which the services of the item are rendered."
    )
    fixed_value_date: ODataDate = Field(
        default=None,
        alias="FixedValueDate",
        description="Fixed value date of the item - the payment terms are calculated from this date.",
    )


class SAPSalesOrderResponseModel(SAPODataModel):
    """An SAP sales order as returned by SAP (API_SALES_ORDER_SRV, OData V2).

    All fields except the sales order number are optional.

    Attributes:
        items (list[SAPSalesOrderItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    order_id: str = Field(
        alias="SalesOrder",
        description="Sales order the record belongs to (e.g. make-to-order production); see get_sales_order().",
    )
    order_type: str | None = Field(
        default=None, alias="SalesOrderType", description="Sales document type, e.g. 'OR' / 'TA' (standard order)."
    )
    sales_organization: str | None = Field(
        default=None,
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    distribution_channel: str | None = Field(
        default=None,
        alias="DistributionChannel",
        description="Distribution channel, e.g. '10' (direct sales). Sales organization + distribution channel + division form the sales area.",
    )
    division: str | None = Field(
        default=None,
        alias="OrganizationDivision",
        description="Division (product line). Sales organization + distribution channel + division form the sales area.",
    )
    sold_to_party: str | None = Field(
        default=None,
        alias="SoldToParty",
        description="Sold-to party - the customer who places the order; see get_customers().",
    )
    customer_reference: str | None = Field(
        default=None, alias="PurchaseOrderByCustomer", description="The customer's purchase order number."
    )
    order_date: ODataDate = Field(default=None, alias="SalesOrderDate", description="Sales order (document) date.")
    requested_delivery_date: ODataDate = Field(
        default=None, alias="RequestedDeliveryDate", description="Requested delivery date."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    total_net_amount: SAPDecimal | None = Field(
        default=None, alias="TotalNetAmount", description="Total net value of the order in the document currency."
    )
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    overall_status: str | None = Field(
        default=None,
        alias="OverallSDProcessStatus",
        description="Overall processing status: 'A' open, 'B' in process, 'C' completed.",
    )
    delivery_status: str | None = Field(
        default=None,
        alias="OverallTotalDeliveryStatus",
        description="Overall delivery status: 'A' not delivered, 'B' partially delivered, 'C' fully delivered.",
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    customer_reference_date: ODataDate = Field(
        default=None,
        alias="CustomerPurchaseOrderDate",
        description="Date of the customer's purchase order.",
    )
    pricing_date: ODataDate = Field(
        default=None, alias="PricingDate", description="Date used for pricing and the exchange rate."
    )
    billing_date: ODataDate = Field(
        default=None, alias="BillingDocumentDate", description="Billing date - the date on which the order is billed."
    )
    services_rendered_date: ODataDate = Field(
        default=None,
        alias="ServicesRenderedDate",
        description="Date on which the services are rendered (e.g. for tax determination).",
    )
    fixed_value_date: ODataDate = Field(
        default=None,
        alias="FixedValueDate",
        description="Fixed value date - the payment terms are calculated from this date.",
    )
    payment_terms: str | None = Field(
        default=None,
        alias="CustomerPaymentTerms",
        description="Terms of payment agreed with the customer, e.g. '0001' (payable immediately) - system specific.",
    )
    reference_document: str | None = Field(
        default=None,
        alias="ReferenceSDDocument",
        description="Preceding sales document the document was created from (e.g. a quotation or contract).",
    )
    items: Annotated[list[SAPSalesOrderItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)] = Field(
        default=None,
        alias="to_Item",
        description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPSalesOrderQueryModel(SAPODataQueryModel):
    """Search criteria for SAP sales orders (API_SALES_ORDER_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "order_id": "SalesOrder {direction}",
        "order_date": "SalesOrderDate {direction}",
        "requested_delivery": "RequestedDeliveryDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_Item"
    sort_by: Literal["order_id", "order_date", "requested_delivery"] = Field(
        default="order_id", description="Sort criterion."
    )
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    order_ids: Annotated[list[SAPCode] | None, ODataCondition("SalesOrder")] = Field(
        default=None, description="Sales order numbers, e.g. ['1234']."
    )
    order_types: Annotated[list[SAPCode] | None, ODataCondition("SalesOrderType")] = Field(
        default=None, description="Sales order types, e.g. ['OR']. System specific."
    )
    sold_to_party: Annotated[SAPCode | None, ODataCondition("SoldToParty")] = Field(
        default=None, description="Customer number of the sold-to party."
    )
    sales_organization: Annotated[SAPCode | None, ODataCondition("SalesOrganization")] = Field(
        default=None, description="Sales organization, e.g. '1010'."
    )
    distribution_channel: Annotated[SAPCode | None, ODataCondition("DistributionChannel")] = Field(
        default=None, description="Distribution channel, e.g. '10'."
    )
    division: Annotated[SAPCode | None, ODataCondition("OrganizationDivision")] = Field(
        default=None, description="Division, e.g. '00'."
    )
    customer_reference: Annotated[str | None, ODataCondition("PurchaseOrderByCustomer")] = Field(
        default=None, description="Customer reference (the customer's purchase order number)."
    )
    order_date_from: Annotated[date | None, ODataCondition("SalesOrderDate", operator="ge")] = Field(
        default=None, description="Only sales orders dated on or after this date."
    )
    order_date_to: Annotated[date | None, ODataCondition("SalesOrderDate", operator="le")] = Field(
        default=None, description="Only sales orders dated on or before this date."
    )
    requested_delivery_from: Annotated[date | None, ODataCondition("RequestedDeliveryDate", operator="ge")] = Field(
        default=None, description="Only sales orders with requested delivery on or after this date."
    )
    requested_delivery_to: Annotated[date | None, ODataCondition("RequestedDeliveryDate", operator="le")] = Field(
        default=None, description="Only sales orders with requested delivery on or before this date."
    )
    process_statuses: Annotated[list[SAPCode] | None, ODataCondition("OverallSDProcessStatus")] = Field(
        default=None,
        description="Overall processing status: 'A' not yet processed, 'B' partially processed, 'C' completely processed.",
    )
    delivery_statuses: Annotated[list[SAPCode] | None, ODataCondition("OverallTotalDeliveryStatus")] = Field(
        default=None,
        description="Overall delivery status: 'A' not delivered, 'B' partially delivered, 'C' completely delivered.",
    )
    expand_items: bool = Field(default=False, description="Also return the items of each sales order.")


# ---------------------------------------------------------------------------
# Sales contracts (API_SALES_CONTRACT_SRV, OData V2)
# ---------------------------------------------------------------------------


class SAPSalesContractItemModel(SAPODataCreateModel):
    """An item of an SAP sales contract (API_SALES_CONTRACT_SRV).

    For quantity contracts the quantity is the target quantity, for value
    contracts the target amount is used.

    """

    item: Numc6 = Field(
        default="10",
        alias="SalesContractItem",
        description="Item number (6 digits, padded), e.g. 10 -> '000010'. Unique within the contract.",
    )
    material: SAPCode = Field(
        alias="Material",
        description="Material (product) number, e.g. 'TG11'.",
        min_length=1,
        max_length=40,
    )
    text: str | None = Field(
        default=None,
        alias="SalesContractItemText",
        description="Short text of the item. Defaults to the material description.",
        max_length=40,
    )
    quantity: SAPDecimal | None = Field(
        default=None,
        alias="RequestedQuantity",
        description="Target quantity (for quantity contracts), e.g. 1000.",
        gt=0,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="RequestedQuantityUnit",
        description="Sales unit (internal SAP unit code, max. 3 characters), e.g. 'ST'. Defaults to the sales unit of the material.",
        max_length=3,
    )
    target_amount: SAPDecimal | None = Field(
        default=None,
        alias="OutlineAgreementTargetAmount",
        description="Target value of the item in the document currency (for value contracts).",
        gt=0,
        decimal_places=2,
    )
    plant: SAPCode | None = Field(
        default=None, alias="ProductionPlant", description="Delivering plant, e.g. '1010'.", max_length=4
    )
    item_category: SAPCode | None = Field(
        default=None,
        alias="SalesContractItemCategory",
        description="Sales document item category. Usually determined automatically - system specific; copy from an existing document if unsure.",
        max_length=4,
    )


class SAPSalesContractModel(SAPODataCreateModel):
    """Data to create an SAP sales contract (API_SALES_CONTRACT_SRV, OData V2).

    The sales contract number is assigned by SAP. Items are optional (e.g. for
    contracts that are only used as a framework).

    See: https://api.sap.com/api/API_SALES_CONTRACT_SRV/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "SalesContractType": "YC",
                    "SalesOrganization": "1000",
                    "DistributionChannel": "10",
                    "OrganizationDivision": "00",
                    "SoldToParty": "50031",
                    "SalesContractValidityStartDate": "2026-11-01",
                    "SalesContractValidityEndDate": "2027-10-31",
                    "to_Item": [{"Material": "P-100", "RequestedQuantity": 1000}],
                }
            ]
        }
    )

    contract_type: SAPCode = Field(
        alias="SalesContractType",
        description="Sales contract type, e.g. 'CQ' (quantity contract), 'WK1' (value contract) or 'YC' - system specific; copy from an existing document if unsure.",
        min_length=1,
        max_length=4,
    )
    sales_organization: SAPCode = Field(
        alias="SalesOrganization",
        description="Sales organization, e.g. '1010'.",
        min_length=1,
        max_length=4,
    )
    distribution_channel: SAPCode = Field(
        alias="DistributionChannel",
        description="Distribution channel, e.g. '10' (direct sales).",
        min_length=1,
        max_length=2,
    )
    division: SAPCode = Field(
        alias="OrganizationDivision",
        description="Division, e.g. '00' (cross-division).",
        min_length=1,
        max_length=2,
    )
    sold_to_party: SAPCode = Field(
        alias="SoldToParty",
        description="Customer number of the sold-to party, e.g. '10100001'.",
        min_length=1,
        max_length=10,
    )
    customer_reference: str | None = Field(
        default=None,
        alias="PurchaseOrderByCustomer",
        description="The customer's reference / purchase order number.",
        max_length=35,
    )
    validity_start_date: ODataV2Date = Field(
        default=None,
        alias="SalesContractValidityStartDate",
        description="Start of the contract validity, e.g. '2026-11-01'.",
    )
    validity_end_date: ODataV2Date = Field(
        default=None,
        alias="SalesContractValidityEndDate",
        description="End of the contract validity, e.g. '2026-11-01'. Must not be before `validity_start_date`.",
    )
    signed_date: ODataV2Date = Field(
        default=None,
        alias="SalesContractSignedDate",
        description="Date the contract was signed, e.g. '2026-11-01'.",
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="CustomerPaymentTerms",
        description="Terms of payment key, e.g. '0001' - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    currency: SAPCode | None = Field(
        default=None,
        alias="TransactionCurrency",
        description="Document currency (ISO code), e.g. 'EUR'. Defaults to the currency of the customer.",
        max_length=5,
    )
    items: Annotated[list[SAPSalesContractItemModel], unique_numbers("item")] = Field(
        default_factory=list,
        alias="to_Item",
        description="Items of the contract (optional). Item numbers must be unique.",
        exclude_if=is_empty,
    )

    @model_validator(mode="after")
    def check_dates(self) -> Self:
        """Validate that the validity end date is not before the validity start date."""

        if self.validity_start_date and self.validity_end_date and self.validity_end_date < self.validity_start_date:
            message = "Validity end date -> {} is before validity start date -> {}".format(
                self.validity_end_date,
                self.validity_start_date,
            )
            raise ValueError(message)

        return self

    # end method definition


class SAPSalesContractItemResponseModel(SAPODataModel):
    """An item of an SAP sales contract as returned by SAP (API_SALES_CONTRACT_SRV)."""

    contract_id: str = Field(alias="SalesContract", description="Sales contract number.")
    item: str = Field(alias="SalesContractItem", description="Item number (6 digits), e.g. '000010'.")
    text: str | None = Field(default=None, alias="SalesContractItemText", description="Short text of the item.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    quantity: SAPDecimal | None = Field(default=None, alias="RequestedQuantity", description="Target quantity.")
    unit: str | None = Field(
        default=None, alias="RequestedQuantityUnit", description="Sales unit (internal SAP unit code)."
    )
    target_amount: SAPDecimal | None = Field(
        default=None, alias="OutlineAgreementTargetAmount", description="Target value of the item."
    )
    net_amount: SAPDecimal | None = Field(
        default=None, alias="NetAmount", description="Net value of the item in the document currency."
    )
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    consumed_quantity: SAPDecimal | None = Field(
        default=None,
        alias="ContractItemConsumedQuantity",
        description="Quantity already released (called off) from the contract.",
    )
    open_quantity: SAPDecimal | None = Field(
        default=None, alias="ContrItemOpenQty", description="Quantity still open for release orders."
    )
    plant: str | None = Field(
        default=None, alias="ProductionPlant", description="Plant in which the material is produced; see get_plants()."
    )
    item_category: str | None = Field(
        default=None, alias="SalesContractItemCategory", description="Sales document item category."
    )
    validity_start_date: ODataDate = Field(
        default=None,
        alias="SalesContractValidityStartDate",
        description="Start of the validity period of the contract item.",
    )
    validity_end_date: ODataDate = Field(
        default=None,
        alias="SalesContractValidityEndDate",
        description="End of the validity period of the contract item.",
    )
    pricing_date: ODataDate = Field(
        default=None, alias="PricingDate", description="Date used for pricing and the exchange rate of the item."
    )
    signed_date: ODataDate = Field(
        default=None, alias="SalesContractSignedDate", description="Date on which the contract item was signed."
    )
    follow_up_action_date: ODataDate = Field(
        default=None,
        alias="SlsContractFollowUpActionDate",
        description="Date of the follow-up action of the contract item.",
    )


class SAPSalesContractResponseModel(SAPODataModel):
    """An SAP sales contract as returned by SAP (API_SALES_CONTRACT_SRV, OData V2).

    Attributes:
        items (list[SAPSalesContractItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    contract_id: str = Field(alias="SalesContract", description="Sales contract number (assigned by SAP).")
    contract_type: str | None = Field(default=None, alias="SalesContractType", description="Sales contract type.")
    sales_organization: str | None = Field(
        default=None,
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    distribution_channel: str | None = Field(
        default=None,
        alias="DistributionChannel",
        description="Distribution channel, e.g. '10' (direct sales). Sales organization + distribution channel + division form the sales area.",
    )
    division: str | None = Field(
        default=None,
        alias="OrganizationDivision",
        description="Division (product line). Sales organization + distribution channel + division form the sales area.",
    )
    sold_to_party: str | None = Field(
        default=None,
        alias="SoldToParty",
        description="Sold-to party - the customer who places the order; see get_customers().",
    )
    customer_reference: str | None = Field(
        default=None, alias="PurchaseOrderByCustomer", description="The customer's reference / purchase order number."
    )
    contract_date: ODataDate = Field(default=None, alias="SalesContractDate", description="Contract (document) date.")
    validity_start_date: ODataDate = Field(
        default=None, alias="SalesContractValidityStartDate", description="Start of the contract validity."
    )
    validity_end_date: ODataDate = Field(
        default=None, alias="SalesContractValidityEndDate", description="End of the contract validity."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    total_net_amount: SAPDecimal | None = Field(
        default=None, alias="TotalNetAmount", description="Total net value of the contract in the document currency."
    )
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    overall_status: str | None = Field(
        default=None,
        alias="OverallSDProcessStatus",
        description="Overall processing status: 'A' open, 'B' in process, 'C' completed.",
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    customer_reference_date: ODataDate = Field(
        default=None,
        alias="CustomerPurchaseOrderDate",
        description="Date of the customer's purchase order.",
    )
    pricing_date: ODataDate = Field(
        default=None, alias="PricingDate", description="Date used for pricing and the exchange rate."
    )
    signed_date: ODataDate = Field(
        default=None, alias="SalesContractSignedDate", description="Date on which the contract was signed."
    )
    follow_up_action_date: ODataDate = Field(
        default=None,
        alias="SlsContractFollowUpActionDate",
        description="Date of the follow-up action of the contract (e.g. renewal or termination).",
    )
    payment_terms: str | None = Field(
        default=None,
        alias="CustomerPaymentTerms",
        description="Terms of payment agreed with the customer, e.g. '0001' (payable immediately) - system specific.",
    )
    items: Annotated[list[SAPSalesContractItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)] = Field(
        default=None,
        alias="to_Item",
        description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPSalesContractQueryModel(SAPODataQueryModel):
    """Search criteria for SAP sales contracts (API_SALES_CONTRACT_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "contract_id": "SalesContract {direction}",
        "validity_end": "SalesContractValidityEndDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_Item"
    sort_by: Literal["contract_id", "validity_end"] = Field(default="contract_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    contract_ids: Annotated[list[SAPCode] | None, ODataCondition("SalesContract")] = Field(
        default=None, description="Sales contract numbers, e.g. ['40000012']."
    )
    contract_types: Annotated[list[SAPCode] | None, ODataCondition("SalesContractType")] = Field(
        default=None, description="Contract types, e.g. ['WK1']. System specific."
    )
    sold_to_party: Annotated[SAPCode | None, ODataCondition("SoldToParty")] = Field(
        default=None, description="Customer number of the sold-to party."
    )
    sales_organization: Annotated[SAPCode | None, ODataCondition("SalesOrganization")] = Field(
        default=None, description="Sales organization, e.g. '1010'."
    )
    distribution_channel: Annotated[SAPCode | None, ODataCondition("DistributionChannel")] = Field(
        default=None, description="Distribution channel, e.g. '10'."
    )
    division: Annotated[SAPCode | None, ODataCondition("OrganizationDivision")] = Field(
        default=None, description="Division, e.g. '00'."
    )
    customer_reference: Annotated[str | None, ODataCondition("PurchaseOrderByCustomer")] = Field(
        default=None, description="Customer reference of the contract."
    )
    valid_on: Annotated[
        date | None,
        ODataCondition(("SalesContractValidityStartDate", "SalesContractValidityEndDate"), operator="valid_on"),
    ] = Field(default=None, description="Only contracts valid on this date (e.g. today for the current ones).")
    expand_items: bool = Field(default=False, description="Also return the items of each contract.")


# ---------------------------------------------------------------------------
# Purchase contracts (API_PURCHASECONTRACT_PROCESS_SRV, OData V2)
# ---------------------------------------------------------------------------


class SAPPurchaseContractItemModel(SAPPurchasingItemModel):
    """An item of an SAP purchase contract (API_PURCHASECONTRACT_PROCESS_SRV).

    An item needs either a material or a short text plus a material group.
    For quantity contracts ("MK") the target quantity is required.

    """

    item: Numc5 = Field(
        default="10",
        alias="PurchaseContractItem",
        description="Item number (5 digits, padded), e.g. 10 -> '00010'. Unique within the contract.",
    )
    text: str | None = Field(
        default=None,
        alias="PurchaseContractItemText",
        description="Short text of the item. Required if no `material` is given; then `material_group` is required too.",
        max_length=40,
    )
    plant: SAPCode | None = Field(
        default=None,
        alias="Plant",
        description="Plant the contract item applies to, e.g. '1010'.",
        max_length=4,
    )
    target_quantity: SAPDecimal | None = Field(
        default=None,
        alias="TargetQuantity",
        description="Target quantity (required for quantity contracts 'MK'), e.g. 100.",
        gt=0,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="OrderQuantityUnit",
        description="Order unit (internal SAP unit code, max. 3 characters), e.g. 'ST'. Defaults to the order unit of the material.",
        max_length=3,
    )
    net_price: SAPDecimal | None = Field(
        default=None,
        alias="ContractNetPriceAmount",
        description="Net price per `price_unit` in the document currency, e.g. 950.00.",
        ge=0,
        decimal_places=2,
    )
    price_unit: SAPDecimal | None = Field(
        default=None,
        alias="NetPriceQuantity",
        description="Quantity the net price refers to, e.g. 100 for a price per 100 pieces. Defaults to 1.",
        gt=0,
    )
    item_category: SAPCode | None = Field(
        default=None,
        alias="PurchasingDocumentItemCategory",
        description="Item category: empty = standard, 'M' material unknown, 'W' material group - system specific; copy from an existing document if unsure.",
        max_length=1,
    )
    tax_code: SAPCode | None = Field(
        default=None,
        alias="TaxCode",
        description="Tax code (country specific), e.g. 'V1' - system specific; copy from an existing document if unsure.",
        max_length=2,
    )


class SAPPurchaseContractModel(SAPODataCreateModel):
    """Data to create an SAP purchase contract (API_PURCHASECONTRACT_PROCESS_SRV, OData V2).

    "MK" is a quantity contract (items need a target quantity), "WK" a value
    contract (the header needs a target amount). The contract number is assigned by SAP.

    See: https://api.sap.com/api/API_PURCHASECONTRACT_PROCESS_SRV/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "CompanyCode": "3000",
                    "PurchasingOrganization": "3000",
                    "PurchasingGroup": "001",
                    "Supplier": "30010",
                    "ValidityStartDate": "2026-11-01",
                    "ValidityEndDate": "2027-10-31",
                    "to_PurchaseContractItem": [
                        {"Material": "R-9000", "Plant": "3000", "TargetQuantity": 100, "ContractNetPriceAmount": 950.0}
                    ],
                }
            ]
        }
    )

    contract_type: SAPCode = Field(
        default="MK",
        alias="PurchaseContractType",
        description="Purchase contract type: 'MK' quantity contract (default), 'WK' value contract - system specific; copy from an existing document if unsure.",
        min_length=1,
        max_length=4,
    )
    company_code: SAPCode = Field(
        alias="CompanyCode", description="Company code, e.g. '1010'.", min_length=1, max_length=4
    )
    purchasing_organization: SAPCode = Field(
        alias="PurchasingOrganization",
        description="Purchasing organization, e.g. '1010'.",
        min_length=1,
        max_length=4,
    )
    purchasing_group: SAPCode = Field(
        alias="PurchasingGroup",
        description="Purchasing group (responsible buyer), e.g. '001'.",
        min_length=1,
        max_length=3,
    )
    supplier: SAPCode = Field(
        alias="Supplier",
        description="Supplier number (business partner, max. 10 characters), e.g. '10300001'.",
        min_length=1,
        max_length=10,
    )
    validity_start_date: ODataV2Date = Field(
        alias="ValidityStartDate",
        description="Start of the contract validity, e.g. '2026-11-01'. Required.",
    )
    validity_end_date: ODataV2Date = Field(
        alias="ValidityEndDate",
        description="End of the contract validity, e.g. '2026-11-01'. Required; must not be before `validity_start_date`.",
    )
    target_amount: SAPDecimal | None = Field(
        default=None,
        alias="PurchaseContractTargetAmount",
        description="Target value of the contract in the document currency (required for value contracts 'WK').",
        gt=0,
        decimal_places=2,
    )
    currency: SAPCode | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO code), e.g. 'EUR'. Defaults to the currency of the supplier.",
        max_length=5,
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="PaymentTerms",
        description="Terms of payment key, e.g. '0001' - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    your_reference: str | None = Field(
        default=None,
        alias="CorrespncExternalReference",
        description="External reference, e.g. the supplier's quotation number.",
        max_length=12,
    )
    items: Annotated[list[SAPPurchaseContractItemModel], unique_numbers("item")] = Field(
        default_factory=list,
        alias="to_PurchaseContractItem",
        description="Items of the contract. Item numbers must be unique.",
        exclude_if=is_empty,
    )

    @model_validator(mode="after")
    def check_dates(self) -> Self:
        """Validate that the validity dates are given and the end date is not before the start date."""

        if not self.validity_start_date or not self.validity_end_date:
            message = "A purchase contract needs a validity start and end date"
            raise ValueError(message)
        if self.validity_end_date < self.validity_start_date:
            message = "Validity end date -> {} is before validity start date -> {}".format(
                self.validity_end_date,
                self.validity_start_date,
            )
            raise ValueError(message)

        return self

    # end method definition


class SAPPurchaseContractItemResponseModel(SAPODataModel):
    """An item of an SAP purchase contract as returned by SAP (API_PURCHASECONTRACT_PROCESS_SRV)."""

    contract_id: str = Field(
        alias="PurchaseContract",
        description="Purchase contract (outline agreement) the item is ordered against; see get_purchase_contract().",
    )
    item: str = Field(
        alias="PurchaseContractItem", description="Item of the purchase contract the item is ordered against."
    )
    text: str | None = Field(default=None, alias="PurchaseContractItemText", description="Short text of the item.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    material_group: str | None = Field(
        default=None,
        alias="MaterialGroup",
        description="Material group - classifies materials and services; used for items without material number (e.g. services).",
    )
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    target_quantity: SAPDecimal | None = Field(default=None, alias="TargetQuantity", description="Target quantity.")
    unit: str | None = Field(
        default=None, alias="OrderQuantityUnit", description="Order unit (internal SAP unit code)."
    )
    net_price: SAPDecimal | None = Field(
        default=None, alias="ContractNetPriceAmount", description="Net price per `price_unit` in the document currency."
    )
    price_unit: SAPDecimal | None = Field(
        default=None, alias="NetPriceQuantity", description="Quantity the net price refers to."
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    consumed_quantity: SAPDecimal | None = Field(
        default=None,
        alias="ContractItemConsumedQuantity",
        description="Quantity already released (called off) from the contract.",
    )
    open_quantity: SAPDecimal | None = Field(
        default=None, alias="ContrItemOpenQty", description="Quantity still open for release orders."
    )
    account_assignment_category: str | None = Field(
        default=None,
        alias="AccountAssignmentCategory",
        description="Account assignment category - what the item is charged to: 'K' cost center, 'F' internal order, 'P' project, empty for stock.",
    )
    item_category: str | None = Field(
        default=None, alias="PurchasingDocumentItemCategory", description="Item category."
    )
    deletion_code: str | None = Field(
        default=None,
        alias="PurchasingContractDeletionCode",
        description="Deletion indicator: 'L' = deleted, 'S' = blocked, empty = active.",
    )
    tax_determination_date: ODataDate = Field(
        default=None, alias="TaxDeterminationDate", description="Date used to determine the tax (rate) of the item."
    )


class SAPPurchaseContractResponseModel(SAPODataModel):
    """An SAP purchase contract as returned by SAP (API_PURCHASECONTRACT_PROCESS_SRV, OData V2).

    Attributes:
        items (list[SAPPurchaseContractItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    contract_id: str = Field(
        alias="PurchaseContract",
        description="Purchase contract (outline agreement) the item is ordered against; see get_purchase_contract().",
    )
    contract_type: str | None = Field(
        default=None,
        alias="PurchaseContractType",
        description="Purchase contract type, e.g. 'MK' (quantity) or 'WK' (value contract).",
    )
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    purchasing_organization: str | None = Field(
        default=None,
        alias="PurchasingOrganization",
        description="Purchasing organization - negotiates the conditions with suppliers; see get_purchasing_organizations().",
    )
    purchasing_group: str | None = Field(
        default=None,
        alias="PurchasingGroup",
        description="Purchasing group - the buyer or group of buyers responsible for the document.",
    )
    supplier: str | None = Field(
        default=None,
        alias="Supplier",
        description="Supplier (vendor) number - a business partner in the supplier role; see get_vendors().",
    )
    validity_start_date: ODataDate = Field(
        default=None, alias="ValidityStartDate", description="Start of the contract validity."
    )
    validity_end_date: ODataDate = Field(
        default=None, alias="ValidityEndDate", description="End of the contract validity."
    )
    target_amount: SAPDecimal | None = Field(
        default=None, alias="PurchaseContractTargetAmount", description="Target value of the contract."
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    processing_status: str | None = Field(
        default=None,
        alias="PurchasingProcessingStatus",
        description="Processing status, e.g. '01' (in process), '02' (active), '05' (released).",
    )
    deletion_code: str | None = Field(
        default=None,
        alias="PurchasingDocumentDeletionCode",
        description="Deletion indicator: 'L' = deleted, empty = active.",
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    quotation_submission_date: ODataDate = Field(
        default=None, alias="QuotationSubmissionDate", description="Date on which the supplier submitted the quotation."
    )
    payment_terms: str | None = Field(
        default=None,
        alias="PaymentTerms",
        description="Terms of payment key, e.g. '0001' (payable immediately) - system specific.",
    )
    items: Annotated[
        list[SAPPurchaseContractItemResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_PurchaseContractItem",
        description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPPurchaseContractQueryModel(SAPODataQueryModel):
    """Search criteria for SAP purchase contracts (API_PURCHASECONTRACT_PROCESS_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "contract_id": "PurchaseContract {direction}",
        "validity_end": "ValidityEndDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_PurchaseContractItem"
    sort_by: Literal["contract_id", "validity_end"] = Field(default="contract_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    contract_ids: Annotated[list[SAPCode] | None, ODataCondition("PurchaseContract")] = Field(
        default=None, description="Purchase contract numbers, e.g. ['4600000012']."
    )
    contract_types: Annotated[list[SAPCode] | None, ODataCondition("PurchaseContractType")] = Field(
        default=None, description="Contract types, e.g. ['MK'] (quantity) or ['WK'] (value). System specific."
    )
    supplier: Annotated[SAPCode | None, ODataCondition("Supplier")] = Field(
        default=None, description="Supplier (vendor) number."
    )
    company_code: Annotated[SAPCode | None, ODataCondition("CompanyCode")] = Field(
        default=None, description="Company code, e.g. '1010'."
    )
    purchasing_organization: Annotated[SAPCode | None, ODataCondition("PurchasingOrganization")] = Field(
        default=None, description="Purchasing organization, e.g. '1010'."
    )
    purchasing_group: Annotated[SAPCode | None, ODataCondition("PurchasingGroup")] = Field(
        default=None, description="Purchasing group (buyer), e.g. '001'."
    )
    valid_on: Annotated[date | None, ODataCondition(("ValidityStartDate", "ValidityEndDate"), operator="valid_on")] = (
        Field(default=None, description="Only contracts valid on this date (e.g. today for the current ones).")
    )
    expand_items: bool = Field(default=False, description="Also return the items of each contract.")


# ---------------------------------------------------------------------------
# Purchase requisitions (API_PURCHASEREQUISITION_2, OData V4)
# ---------------------------------------------------------------------------


class SAPPurchaseRequisitionAccountAssignmentModel(SAPODataCreateModel):
    """An account assignment of a purchase requisition item (API_PURCHASEREQUISITION_2).

    Required if the item has an account assignment category, e.g. "K" (cost center)
    requires a cost center and a G/L account.

    """

    number: Numc2 = Field(
        default="1",
        alias="PurchaseReqnAcctAssgmtNumber",
        description="Account assignment number (2 digits, padded), e.g. 1 -> '01'. Unique within the item.",
    )
    cost_center: SAPCode | None = Field(
        default=None,
        alias="CostCenter",
        description="Cost center to charge, e.g. '10101101'. Required for account assignment category 'K'.",
        max_length=10,
    )
    gl_account: SAPCode | None = Field(
        default=None,
        alias="GLAccount",
        description="G/L account to post to, e.g. '61003000'. Usually required for cost center assignments.",
        max_length=10,
    )
    internal_order: SAPCode | None = Field(
        default=None,
        alias="OrderID",
        description="Internal order (CO order) to charge. Used with account assignment category 'F'.",
        max_length=12,
    )
    wbs_element: SAPCode | None = Field(
        default=None,
        alias="WBSElementExternalID",
        description="WBS element (project) to charge, external ID. Used with account assignment category 'P'.",
        max_length=24,
    )
    quantity: SAPDecimal | None = Field(
        default=None,
        alias="Quantity",
        description="Quantity assigned to this account (for multiple account assignment).",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    distribution_percent: SAPDecimal | None = Field(
        default=None,
        alias="MultipleAcctAssgmtDistrPercent",
        description="Percentage of the item assigned to this account (0-100, for multiple account assignment).",
        gt=0,
        le=100,
        decimal_places=1,
    )


class SAPPurchaseRequisitionItemModel(SAPPurchasingItemModel):
    """An item of an SAP purchase requisition (API_PURCHASEREQUISITION_2, OData V4).

    An item needs either a material or a short text plus a material group.
    In contrast to purchase orders, the delivery date is part of the item.

    """

    item: Numc5 = Field(
        default="10",
        alias="PurchaseRequisitionItem",
        description="Item number (5 digits, padded), e.g. 10 -> '00010'. Unique within the requisition.",
    )
    text: str | None = Field(
        default=None,
        alias="PurchaseRequisitionItemText",
        description="Short text of the item. Required if no `material` is given; then `material_group` is required too.",
        max_length=40,
    )
    quantity: SAPDecimal = Field(
        alias="RequestedQuantity",
        description="Requested quantity (greater than 0), e.g. 10.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="BaseUnit",
        description="Unit as stored in SAP (internal unit code, max. 3 characters), e.g. 'ST'. Defaults to the base unit of the material.",
        max_length=3,
    )
    price: SAPDecimal | None = Field(
        default=None,
        alias="PurchaseRequisitionPrice",
        description="Valuation price per `price_unit` in `currency`, e.g. 25.00. Required for items without material.",
        ge=0,
        max_digits=11,
        decimal_places=2,
    )
    price_unit: SAPDecimal | None = Field(
        default=None,
        alias="PurReqnPriceQuantity",
        description="Quantity the price refers to, e.g. 100 for a price per 100 pieces. Defaults to 1.",
        gt=0,
        max_digits=5,
        decimal_places=0,
    )
    currency: SAPCode | None = Field(
        default=None,
        alias="PurReqnItemCurrency",
        description="Currency of the price (ISO code), e.g. 'EUR'.",
        max_length=5,
    )
    delivery_date: date | None = Field(
        default=None, alias="DeliveryDate", description="Requested delivery date, e.g. '2026-11-01'."
    )
    plant: SAPCode | None = Field(
        default=None, alias="Plant", description="Receiving plant, e.g. '1010'.", max_length=4
    )
    storage_location: SAPCode | None = Field(
        default=None,
        alias="StorageLocation",
        description="Receiving storage location, e.g. '101A'.",
        max_length=4,
    )
    company_code: SAPCode | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code, e.g. '1010'. Usually derived from the plant.",
        max_length=4,
    )
    purchasing_organization: SAPCode | None = Field(
        default=None,
        alias="PurchasingOrganization",
        description="Purchasing organization, e.g. '1010'.",
        max_length=4,
    )
    purchasing_group: SAPCode | None = Field(
        default=None,
        alias="PurchasingGroup",
        description="Purchasing group (responsible buyer), e.g. '001'.",
        max_length=3,
    )
    item_category: SAPCode | None = Field(
        default=None,
        alias="PurchasingDocumentItemCategory",
        description="Item category: empty = standard, 'K' consignment, 'L' subcontracting, 'D' service - system specific; copy from an existing document if unsure.",
        max_length=1,
    )
    desired_supplier: SAPCode | None = Field(
        default=None,
        alias="Supplier",
        description="Desired (proposed) supplier number - a suggestion for the buyer.",
        max_length=10,
    )
    fixed_supplier: SAPCode | None = Field(
        default=None,
        alias="FixedSupplier",
        description="Fixed supplier number - the purchase order will be placed with this supplier.",
        max_length=10,
    )
    requisitioner: str | None = Field(
        default=None,
        alias="RequisitionerName",
        description="Name of the requisitioner (free text, max. 12 characters).",
        max_length=12,
    )
    account_assignments: Annotated[
        list[SAPPurchaseRequisitionAccountAssignmentModel],
        unique_numbers("number"),
    ] = Field(
        default_factory=list,
        alias="_PurchaseReqnAcctAssgmt",
        description="Account assignments (who pays). Require `account_assignment_category`. Numbers must be unique within the item.",
        exclude_if=is_empty,
    )


class SAPPurchaseRequisitionModel(SAPODataCreateModel):
    """Data to create an SAP purchase requisition (API_PURCHASEREQUISITION_2, OData V4).

    The purchase requisition number is assigned by SAP. Items can only be created
    together with the purchase requisition.

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "PurReqnDescription": "Notebook web cams",
                    "_PurchaseRequisitionItem": [
                        {
                            "Material": "R-9010",
                            "RequestedQuantity": 10,
                            "Plant": "3000",
                            "PurchasingGroup": "003",
                            "DeliveryDate": "2026-11-01",
                        }
                    ],
                }
            ]
        }
    )

    requisition_type: SAPCode = Field(
        default="NB",
        alias="PurchaseRequisitionType",
        description="Purchase requisition type, 'NB' (standard, default) - system specific; copy from an existing document if unsure.",
        min_length=1,
        max_length=4,
    )
    description: str | None = Field(
        default=None,
        alias="PurReqnDescription",
        description="Description of the requisition, e.g. 'Notebook web cams'.",
        max_length=40,
    )
    header_note: str | None = Field(
        default=None, alias="PurReqnHeaderNote", description="Header note (long text) of the requisition."
    )
    items: Annotated[list[SAPPurchaseRequisitionItemModel], unique_numbers("item")] = Field(
        alias="_PurchaseRequisitionItem",
        description="Items of the requisition (at least one). Item numbers must be unique.",
        min_length=1,
    )


class SAPPurchaseRequisitionAccountAssignmentResponseModel(SAPODataModel):
    """An account assignment of a purchase requisition item as returned by SAP (API_PURCHASEREQUISITION_2)."""

    requisition_id: str = Field(
        alias="PurchaseRequisition",
        description="Purchase requisition (internal request) the item was created from; see get_purchase_requisition().",
    )
    item: str = Field(
        alias="PurchaseRequisitionItem", description="Item of the purchase requisition the item was created from."
    )
    number: str = Field(
        alias="PurchaseReqnAcctAssgmtNumber", description="Account assignment number (2 digits), e.g. '01'."
    )
    cost_center: str | None = Field(
        default=None,
        alias="CostCenter",
        description="Cost center that is charged with the costs; see get_cost_center().",
    )
    gl_account: str | None = Field(
        default=None, alias="GLAccount", description="G/L account the values are posted to; see get_gl_account()."
    )
    internal_order: str | None = Field(
        default=None, alias="OrderID", description="Internal order (CO order) that is charged with the costs."
    )
    wbs_element: str | None = Field(
        default=None,
        alias="WBSElementExternalID",
        description="WBS element (element of a project structure) that is charged with the costs.",
    )
    quantity: SAPDecimal | None = Field(
        default=None, alias="Quantity", description="Quantity assigned to this account."
    )
    distribution_percent: SAPDecimal | None = Field(
        default=None,
        alias="MultipleAcctAssgmtDistrPercent",
        description="Percentage of the item assigned to this account.",
    )


class SAPPurchaseRequisitionItemResponseModel(SAPODataModel):
    """An item of an SAP purchase requisition as returned by SAP (API_PURCHASEREQUISITION_2).

    Attributes:
        account_assignments:
            None if they have not been requested ($expand), otherwise a (possibly empty) list.

    """

    requisition_id: str = Field(
        alias="PurchaseRequisition",
        description="Purchase requisition (internal request) the item was created from; see get_purchase_requisition().",
    )
    item: str = Field(
        alias="PurchaseRequisitionItem", description="Item of the purchase requisition the item was created from."
    )
    text: str | None = Field(default=None, alias="PurchaseRequisitionItemText", description="Short text of the item.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    material_group: str | None = Field(
        default=None,
        alias="MaterialGroup",
        description="Material group - classifies materials and services; used for items without material number (e.g. services).",
    )
    quantity: SAPDecimal | None = Field(default=None, alias="RequestedQuantity", description="Requested quantity.")
    unit: str | None = Field(default=None, alias="BaseUnit", description="Unit (internal SAP unit code).")
    price: SAPDecimal | None = Field(
        default=None, alias="PurchaseRequisitionPrice", description="Valuation price per `price_unit`."
    )
    price_unit: SAPDecimal | None = Field(
        default=None, alias="PurReqnPriceQuantity", description="Quantity the price refers to."
    )
    currency: str | None = Field(
        default=None, alias="PurReqnItemCurrency", description="Currency of the price (ISO code)."
    )
    net_amount: SAPDecimal | None = Field(default=None, alias="ItemNetAmount", description="Net value of the item.")
    delivery_date: date | None = Field(default=None, alias="DeliveryDate", description="Requested delivery date.")
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    purchasing_organization: str | None = Field(
        default=None,
        alias="PurchasingOrganization",
        description="Purchasing organization - negotiates the conditions with suppliers; see get_purchasing_organizations().",
    )
    purchasing_group: str | None = Field(
        default=None,
        alias="PurchasingGroup",
        description="Purchasing group - the buyer or group of buyers responsible for the document.",
    )
    account_assignment_category: str | None = Field(
        default=None,
        alias="AccountAssignmentCategory",
        description="Account assignment category - what the item is charged to: 'K' cost center, 'F' internal order, 'P' project, empty for stock.",
    )
    item_category: str | None = Field(
        default=None, alias="PurchasingDocumentItemCategory", description="Item category."
    )
    desired_supplier: str | None = Field(
        default=None,
        alias="Supplier",
        description="Supplier (vendor) number - a business partner in the supplier role; see get_vendors().",
    )
    fixed_supplier: str | None = Field(
        default=None, alias="FixedSupplier", description="Supplier fixed as source of supply for the procurement."
    )
    requisitioner: str | None = Field(default=None, alias="RequisitionerName", description="Name of the requisitioner.")
    processing_status: str | None = Field(
        default=None,
        alias="ProcessingStatus",
        description="Processing status: 'N' not edited, 'B' purchase order created, 'A' RFQ created.",
    )
    release_status: str | None = Field(
        default=None, alias="PurReqnReleaseStatus", description="Release (approval) status of the item."
    )
    purchase_order: str | None = Field(
        default=None,
        alias="PurchasingDocument",
        description="Purchasing document (e.g. purchase order) that procures the planned quantity.",
    )
    purchase_order_item: str | None = Field(
        default=None,
        alias="PurchasingDocumentItem",
        description="Item of the purchasing document.",
    )
    is_deleted: SAPFlag = Field(default=None, alias="IsDeleted", description="True if the item has been deleted.")
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    creation_date: date | None = Field(
        default=None, alias="PurReqCreationDate", description="Date the record was created in SAP."
    )
    storage_location: str | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location within the plant where the material is stored; see get_storage_locations().",
    )
    account_assignments: list[SAPPurchaseRequisitionAccountAssignmentResponseModel] | None = Field(
        default=None,
        alias="_PurchaseReqnAcctAssgmt",
        description="Account assignments. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    release_date: ODataDate = Field(
        default=None,
        alias="PurchaseRequisitionReleaseDate",
        description="Date on which the item was released (approved) for purchasing.",
    )
    performance_period_start_date: ODataDate = Field(
        default=None,
        alias="PerformancePeriodStartDate",
        description="Start of the period of performance (for services).",
    )
    performance_period_end_date: ODataDate = Field(
        default=None, alias="PerformancePeriodEndDate", description="End of the period of performance (for services)."
    )


class SAPPurchaseRequisitionResponseModel(SAPODataModel):
    """An SAP purchase requisition as returned by SAP (API_PURCHASEREQUISITION_2, OData V4).

    Attributes:
        items (list[SAPPurchaseRequisitionItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    requisition_id: str = Field(
        alias="PurchaseRequisition",
        description="Purchase requisition (internal request) the item was created from; see get_purchase_requisition().",
    )
    requisition_type: str | None = Field(
        default=None, alias="PurchaseRequisitionType", description="Purchase requisition type, e.g. 'NB' (standard)."
    )
    description: str | None = Field(
        default=None, alias="PurReqnDescription", description="Description of the requisition."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    items: list[SAPPurchaseRequisitionItemResponseModel] | None = Field(
        default=None,
        alias="_PurchaseRequisitionItem",
        description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPPurchaseRequisitionQueryModel(SAPODataQueryModel):
    """Search criteria for SAP purchase requisitions (API_PURCHASEREQUISITION_2, OData V4)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "requisition_id": "PurchaseRequisition {direction}",
        "last_change": "LastChangeDateTime {direction}",
    }
    EXPAND: ClassVar[str] = "_PurchaseRequisitionItem($expand=_PurchaseReqnAcctAssgmt)"
    sort_by: Literal["requisition_id", "last_change"] = Field(default="requisition_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    requisition_ids: Annotated[list[SAPCode] | None, ODataCondition("PurchaseRequisition")] = Field(
        default=None, description="Purchase requisition numbers, e.g. ['10000123']."
    )
    requisition_types: Annotated[list[SAPCode] | None, ODataCondition("PurchaseRequisitionType")] = Field(
        default=None, description="Requisition types, e.g. ['NB']. System specific."
    )
    description_contains: Annotated[str | None, ODataCondition("PurReqnDescription", operator="contains")] = Field(
        default=None, description="Text contained in the requisition description (case-sensitive)."
    )
    material: Annotated[SAPCode | None, ODataCondition("Material", path="_PurchaseRequisitionItem")] = Field(
        default=None, description="Only requisitions with an item for this material."
    )
    plant: Annotated[SAPCode | None, ODataCondition("Plant", path="_PurchaseRequisitionItem")] = Field(
        default=None, description="Only requisitions with an item for this plant."
    )
    supplier: Annotated[SAPCode | None, ODataCondition("Supplier", path="_PurchaseRequisitionItem")] = Field(
        default=None, description="Only requisitions with an item for this (desired) supplier."
    )
    purchasing_group: Annotated[SAPCode | None, ODataCondition("PurchasingGroup", path="_PurchaseRequisitionItem")] = (
        Field(default=None, description="Only requisitions with an item for this purchasing group.")
    )
    created_by: Annotated[SAPCode | None, ODataCondition("CreatedByUser", path="_PurchaseRequisitionItem")] = Field(
        default=None, description="Only requisitions with an item created by this SAP user."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each requisition.")


# ---------------------------------------------------------------------------
# Status actions (see the change_<object>_status() methods of the SAP class)
# ---------------------------------------------------------------------------


class SAPMaintenanceOrderAction(StrEnum):
    """Status actions for maintenance orders (function imports of API_MAINTENANCEORDER).

    Values (SAP function names) and their effect on the order:
    * ReleaseMaintenanceOrder: release the order for execution (status REL).
    * ScheduleMaintenanceOrder: schedule the order (calculate the operation dates).
    * SetMaintOrderToReadyForSchedg / ResetMaintOrderStsRdyForSchedg: set / reset "ready for scheduling".
    * SubmitMaintOrderForApproval: submit the order for approval.
    * ApproveMaintenanceOrder / RejectMaintenanceOrder: approve / reject a submitted order.
    * SetMaintOrderStatusToLocked / SetMaintOrderStatusToUnlocked: lock (LKD) / unlock the order.
    * SetMaintOrdToMainWorkComplete / ResetMaintOrdStsMainWorkCmplt: set / reset "main work completed".
    * SetMaintOrdToTechCompleted / ResetMaintOrdStsTechCompleted: complete technically (TECO) / undo it.
    * SetMaintOrderStatusToClosed / ResetMaintOrderStatusClosed: close (CLSD, business completion) / undo it.
    * SetMaintOrdStsToMrkdForDeltn / ResetMaintOrdStsMrkdForDeltn: set / reset the deletion flag (DLFL).
    * SetMaintOrderToDoNotExecute: mark the order as "do not execute" (it will not be carried out).

    Some actions accept optional parameters (e.g. "MaintOrderReferenceDateTime" or
    "AssignedMaintNotifIsToBeClosed") - pass them to change_maintenance_order_status().

    """

    RELEASE = "ReleaseMaintenanceOrder"
    SCHEDULE = "ScheduleMaintenanceOrder"
    SET_READY_FOR_SCHEDULING = "SetMaintOrderToReadyForSchedg"
    RESET_READY_FOR_SCHEDULING = "ResetMaintOrderStsRdyForSchedg"
    SUBMIT_FOR_APPROVAL = "SubmitMaintOrderForApproval"
    APPROVE = "ApproveMaintenanceOrder"
    REJECT = "RejectMaintenanceOrder"
    LOCK = "SetMaintOrderStatusToLocked"
    UNLOCK = "SetMaintOrderStatusToUnlocked"
    MAIN_WORK_COMPLETE = "SetMaintOrdToMainWorkComplete"
    RESET_MAIN_WORK_COMPLETE = "ResetMaintOrdStsMainWorkCmplt"
    TECHNICALLY_COMPLETE = "SetMaintOrdToTechCompleted"
    RESET_TECHNICALLY_COMPLETE = "ResetMaintOrdStsTechCompleted"
    CLOSE = "SetMaintOrderStatusToClosed"
    RESET_CLOSED = "ResetMaintOrderStatusClosed"
    MARK_FOR_DELETION = "SetMaintOrdStsToMrkdForDeltn"
    RESET_MARKED_FOR_DELETION = "ResetMaintOrdStsMrkdForDeltn"
    DO_NOT_EXECUTE = "SetMaintOrderToDoNotExecute"


class SAPMaintenanceNotificationAction(StrEnum):
    """Status actions for maintenance notifications (actions of API_MAINTNOTIFICATION).

    Values (SAP function names) and their effect on the notification:
    * CompleteMaintNotification: complete the notification (status NOCO).
    * SetMaintNotifToInProcess: put the notification in process (status NOPR).

    """

    COMPLETE = "CompleteMaintNotification"
    SET_IN_PROCESS = "SetMaintNotifToInProcess"


class SAPMaintenancePlanAction(StrEnum):
    """Status / scheduling actions for maintenance plans (actions of API_MAINTENANCEPLAN).

    Values (SAP function names) and their effect on the plan:
    * StartMaintPlnSchedule: start scheduling - generates the maintenance calls from the scheduling start date.
    * RestartMaintPlnSchedule: restart scheduling with a new start date.
    * SetMaintPlanStatusToActive / SetMaintPlanStatusToInactive: activate / deactivate the plan (no calls if inactive).
    * SetMainPlanStsToMrkdForDeltn / ResetMaintPlanStsMrkdForDeltn: set / reset the deletion flag.

    """

    START_SCHEDULING = "StartMaintPlnSchedule"
    RESTART_SCHEDULING = "RestartMaintPlnSchedule"
    ACTIVATE = "SetMaintPlanStatusToActive"
    DEACTIVATE = "SetMaintPlanStatusToInactive"
    MARK_FOR_DELETION = "SetMainPlanStsToMrkdForDeltn"
    RESET_MARKED_FOR_DELETION = "ResetMaintPlanStsMrkdForDeltn"


class SAPProductionOrderAction(StrEnum):
    """Status actions for production orders (function imports of API_PRODUCTION_ORDER_2_SRV).

    Values (SAP function names) and their effect on the order:
    * ReleaseOrder: release the order for production (status REL).
    * TechlyCmpltOrder: complete the order technically (status TECO) - no further production.
    * CloseOrder: close the order (status CLSD) - no further postings.
    * DeletionFlagOrder: set the deletion flag (status DLFL).
    * DeletionIndOrder: set the deletion indicator (status DLT) - the order can be archived.
    * DiscardOrder: discard (cancel) the order.
    * DeliveryCompletedOrder: set "delivery completed" (status DLV) - no further goods receipts expected.
    * OrderReleasedByMES: record that the order has been released by a Manufacturing Execution System.

    """

    RELEASE = "ReleaseOrder"
    TECHNICALLY_COMPLETE = "TechlyCmpltOrder"
    CLOSE = "CloseOrder"
    SET_DELETION_FLAG = "DeletionFlagOrder"
    SET_DELETION_INDICATOR = "DeletionIndOrder"
    DISCARD = "DiscardOrder"
    DELIVERY_COMPLETED = "DeliveryCompletedOrder"
    RELEASED_BY_MES = "OrderReleasedByMES"


# ---------------------------------------------------------------------------
# Goods movements / material documents (API_MATERIAL_DOCUMENT_SRV, OData V2)
# ---------------------------------------------------------------------------


class SAPGoodsMovementItemModel(SAPODataCreateModel):
    """An item of a goods movement (material document item, API_MATERIAL_DOCUMENT_SRV).

    The movement type defines the business transaction, e.g. 101 (goods receipt for a
    purchase order - with purchase order, item and reference document type "B"),
    201 (goods issue to a cost center), 261 (goods issue to a production order) or
    311 (transfer posting between storage locations).

    """

    movement_type: SAPCode = Field(
        alias="GoodsMovementType",
        description="Movement type, e.g. '101' (goods receipt for purchase order), '201' (issue to cost center), '261' (issue to order), '311' (transfer) - system specific; copy from an existing document if unsure.",
        min_length=1,
        max_length=3,
    )
    material: SAPCode | None = Field(
        default=None,
        alias="Material",
        description="Material (product) number, e.g. 'TG11'.",
        max_length=40,
    )
    plant: SAPCode | None = Field(default=None, alias="Plant", description="Plant, e.g. '1010'.", max_length=4)
    storage_location: SAPCode | None = Field(
        default=None, alias="StorageLocation", description="Storage location, e.g. '101A'.", max_length=4
    )
    batch: SAPCode | None = Field(
        default=None,
        alias="Batch",
        description="Batch number - only for batch-managed materials.",
        max_length=10,
    )
    quantity: SAPDecimal = Field(
        alias="QuantityInEntryUnit",
        description="Quantity in the entry unit (greater than 0), e.g. 20.",
        gt=0,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="EntryUnit",
        description="Entry unit (internal SAP unit code, max. 3 characters), e.g. 'ST'. Defaults to the base unit of the material.",
        max_length=3,
    )
    reference_document_type: SAPCode | None = Field(
        default=None,
        alias="GoodsMovementRefDocType",
        description="Reference document type: 'B' purchase order (with movement type 101), 'F' production order, empty = none.",
        max_length=1,
    )
    purchase_order: SAPCode | None = Field(
        default=None,
        alias="PurchaseOrder",
        description="Purchase order number for goods receipts, e.g. '4500000001'.",
        max_length=10,
    )
    purchase_order_item: Numc5 | None = Field(
        default=None,
        alias="PurchaseOrderItem",
        description="Purchase order item number (5 digits, padded), e.g. 10 -> '00010'.",
    )
    manufacturing_order: SAPCode | None = Field(
        default=None,
        alias="ManufacturingOrder",
        description="Production / maintenance order number for goods issues or receipts.",
        max_length=12,
    )
    reservation: SAPCode | None = Field(
        default=None,
        alias="Reservation",
        description="Reservation number the movement refers to.",
        max_length=10,
    )
    reservation_item: Numc4 | None = Field(
        default=None,
        alias="ReservationItem",
        description="Reservation item number (4 digits, padded), e.g. 1 -> '0001'.",
    )
    cost_center: SAPCode | None = Field(
        default=None,
        alias="CostCenter",
        description="Cost center for goods issues to a cost center (movement type 201).",
        max_length=10,
    )
    supplier: SAPCode | None = Field(default=None, alias="Supplier", description="Supplier number.", max_length=10)
    customer: SAPCode | None = Field(default=None, alias="Customer", description="Customer number.", max_length=10)
    reason_code: SAPCode | None = Field(
        default=None,
        alias="GoodsMovementReasonCode",
        description="Reason for the movement, e.g. for scrapping or returns - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    receiving_plant: SAPCode | None = Field(
        default=None,
        alias="IssuingOrReceivingPlant",
        description="Receiving plant of a transfer posting, e.g. '1010'.",
        max_length=4,
    )
    receiving_storage_location: SAPCode | None = Field(
        default=None,
        alias="IssuingOrReceivingStorageLoc",
        description="Receiving storage location of a transfer posting, e.g. '101B'.",
        max_length=4,
    )
    receiving_material: SAPCode | None = Field(
        default=None,
        alias="IssgOrRcvgMaterial",
        description="Receiving material of a transfer posting (material to material).",
        max_length=40,
    )
    receiving_batch: SAPCode | None = Field(
        default=None, alias="IssgOrRcvgBatch", description="Receiving batch of a transfer posting.", max_length=10
    )
    text: str | None = Field(default=None, alias="MaterialDocumentItemText", description="Item text.", max_length=50)
    is_completely_delivered: bool | None = Field(
        default=None,
        alias="IsCompletelyDelivered",
        description="True to set the 'delivery completed' indicator on the purchase / production order item.",
    )


class SAPGoodsMovementModel(SAPODataCreateModel):
    """Data to post a goods movement (material document, API_MATERIAL_DOCUMENT_SRV, OData V2).

    The goods movement code defines the kind of posting: "01" goods receipt for a
    purchase order, "02" goods receipt for a production order, "03" goods issue,
    "04" transfer posting, "05" other goods receipts, "06" reversal of goods movements,
    "07" subsequent adjustment. The material document number is assigned by SAP.

    See: https://api.sap.com/api/API_MATERIAL_DOCUMENT_SRV/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "GoodsMovementCode": "01",
                    "PostingDate": "2026-11-01",
                    "MaterialDocumentHeaderText": "GR for PO 4500000001",
                    "to_MaterialDocumentItem": [
                        {
                            "GoodsMovementType": "101",
                            "Material": "R-9010",
                            "Plant": "3000",
                            "StorageLocation": "0001",
                            "QuantityInEntryUnit": 20,
                            "EntryUnit": "ST",
                            "PurchaseOrder": "4500000001",
                            "PurchaseOrderItem": "10",
                            "GoodsMovementRefDocType": "B",
                        }
                    ],
                }
            ]
        }
    )

    movement_code: Literal["01", "02", "03", "04", "05", "06", "07"] = Field(
        alias="GoodsMovementCode",
        description="Goods movement code (kind of posting): '01' goods receipt for purchase order, '02' goods receipt for production order, '03' goods issue, '04' transfer posting, '05' other goods receipts, '06' reversal of goods movements, '07' subsequent adjustment.",
    )
    posting_date: ODataV2Date = Field(
        default=None,
        alias="PostingDate",
        description="Posting date, e.g. '2026-11-01'. Defaults to today.",
    )
    document_date: ODataV2Date = Field(
        default=None,
        alias="DocumentDate",
        description="Document date, e.g. '2026-11-01'. Defaults to today.",
    )
    header_text: str | None = Field(
        default=None,
        alias="MaterialDocumentHeaderText",
        description="Header text of the material document.",
        max_length=25,
    )
    reference_document: str | None = Field(
        default=None,
        alias="ReferenceDocument",
        description="Reference document number, e.g. the delivery note number.",
        max_length=16,
    )
    items: list[SAPGoodsMovementItemModel] = Field(
        alias="to_MaterialDocumentItem", description="Items of the goods movement (at least one).", min_length=1
    )


class SAPGoodsMovementItemResponseModel(SAPODataModel):
    """An item of a material document as returned by SAP (API_MATERIAL_DOCUMENT_SRV)."""

    document_year: str = Field(
        alias="MaterialDocumentYear", description="Year of the material document (4 digits), e.g. '2026'."
    )
    document: str = Field(alias="MaterialDocument", description="Material document number, e.g. '4900000001'.")
    item: str = Field(
        alias="MaterialDocumentItem", description="Material document item number (4 digits), e.g. '0001'."
    )
    movement_type: str | None = Field(
        default=None,
        alias="GoodsMovementType",
        description="Movement type, e.g. '101' (goods receipt for purchase order).",
    )
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    storage_location: str | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location within the plant where the material is stored; see get_storage_locations().",
    )
    batch: str | None = Field(
        default=None,
        alias="Batch",
        description="Batch - a quantity of the material produced together with uniform properties (batch-managed materials only).",
    )
    quantity: SAPDecimal | None = Field(
        default=None, alias="QuantityInEntryUnit", description="Quantity in the entry unit."
    )
    unit: str | None = Field(default=None, alias="EntryUnit", description="Entry unit (internal SAP unit code).")
    base_quantity: SAPDecimal | None = Field(
        default=None, alias="QuantityInBaseUnit", description="Quantity in the base unit of the material."
    )
    base_unit: str | None = Field(
        default=None, alias="MaterialBaseUnit", description="Base unit of the material (internal SAP unit code)."
    )
    purchase_order: str | None = Field(default=None, alias="PurchaseOrder", description="Purchase order number.")
    purchase_order_item: str | None = Field(
        default=None, alias="PurchaseOrderItem", description="Purchase order item number."
    )
    manufacturing_order: str | None = Field(
        default=None, alias="ManufacturingOrder", description="Production / maintenance order number."
    )
    cost_center: str | None = Field(
        default=None,
        alias="CostCenter",
        description="Cost center that is charged with the costs; see get_cost_center().",
    )
    supplier: str | None = Field(
        default=None,
        alias="Supplier",
        description="Supplier (vendor) number - a business partner in the supplier role; see get_vendors().",
    )
    amount: SAPDecimal | None = Field(
        default=None, alias="GdsMvtExtAmtInCoCodeCrcy", description="Value of the movement in company code currency."
    )
    currency: str | None = Field(
        default=None, alias="CompanyCodeCurrency", description="Company code currency (ISO code)."
    )
    is_cancelled: bool | None = Field(
        default=None,
        alias="GoodsMovementIsCancelled",
        description="True if the movement has been reversed (cancelled).",
    )
    text: str | None = Field(default=None, alias="MaterialDocumentItemText", description="Item text.")
    shelf_life_expiration_date: ODataDate = Field(
        default=None,
        alias="ShelfLifeExpirationDate",
        description="Shelf life expiration or best-before date of the batch.",
    )
    manufacture_date: ODataDate = Field(
        default=None, alias="ManufactureDate", description="Date of manufacture of the batch."
    )
    reservation: str | None = Field(
        default=None,
        alias="Reservation",
        description="Reservation - material reserved for a later goods issue (e.g. for an order).",
    )
    reservation_item: str | None = Field(default=None, alias="ReservationItem", description="Item of the reservation.")
    receiving_plant: str | None = Field(
        default=None, alias="IssuingOrReceivingPlant", description="Receiving (or issuing) plant of a transfer posting."
    )
    receiving_storage_location: str | None = Field(
        default=None,
        alias="IssuingOrReceivingStorageLoc",
        description="Receiving (or issuing) storage location of a transfer posting.",
    )
    reversed_document: str | None = Field(
        default=None,
        alias="ReversedMaterialDocument",
        description="Material document reversed (cancelled) by this item - set on reversal documents.",
    )
    reversed_document_year: str | None = Field(
        default=None,
        alias="ReversedMaterialDocumentYear",
        description="Year of the material document reversed (cancelled) by this item.",
    )


class SAPGoodsMovementResponseModel(SAPODataModel):
    """A material document (goods movement) as returned by SAP (API_MATERIAL_DOCUMENT_SRV, OData V2).

    Attributes:
        items (list[SAPGoodsMovementItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    document_year: str = Field(
        alias="MaterialDocumentYear",
        description="Year of the material document (4 digits), e.g. '2026'. Part of the key.",
    )
    document: str = Field(
        alias="MaterialDocument",
        description="Material document number (assigned by SAP), e.g. '4900000001'. Part of the key.",
    )
    movement_code: str | None = Field(
        default=None,
        alias="GoodsMovementCode",
        description="Goods movement code, e.g. '01' (goods receipt for purchase order).",
    )
    posting_date: ODataDate = Field(default=None, alias="PostingDate", description="Posting date.")
    document_date: ODataDate = Field(default=None, alias="DocumentDate", description="Document date.")
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    header_text: str | None = Field(
        default=None, alias="MaterialDocumentHeaderText", description="Header text of the material document."
    )
    reference_document: str | None = Field(
        default=None, alias="ReferenceDocument", description="Reference document number, e.g. the delivery note number."
    )
    creation_time: ODataTime = Field(
        default=None,
        alias="CreationTime",
        description="Time when the material document was entered (see creation_date).",
    )
    items: Annotated[
        list[SAPGoodsMovementItemResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_MaterialDocumentItem",
        description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPGoodsMovementQueryModel(SAPODataQueryModel):
    """Search criteria for SAP goods movements / material documents (API_MATERIAL_DOCUMENT_SRV). Material and plant are item properties and cannot be searched."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "document": "MaterialDocumentYear {direction},MaterialDocument {direction}",
        "posting_date": "PostingDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_MaterialDocumentItem"
    sort_by: Literal["document", "posting_date"] = Field(default="document", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    document_year: Annotated[SAPCode | None, ODataCondition("MaterialDocumentYear")] = Field(
        default=None, description="Year of the material documents, e.g. '2026'."
    )
    documents: Annotated[list[SAPCode] | None, ODataCondition("MaterialDocument")] = Field(
        default=None, description="Material document numbers, e.g. ['4900000123']."
    )
    movement_codes: Annotated[list[SAPCode] | None, ODataCondition("GoodsMovementCode")] = Field(
        default=None,
        description="Goods movement codes: '01' goods receipt for purchase order, '02' goods receipt for production order, '03' goods issue, '04' transfer posting, '05' other goods receipt, '06' reversal, '07' subsequent adjustment.",
    )
    posting_from: Annotated[date | None, ODataCondition("PostingDate", operator="ge")] = Field(
        default=None, description="Only material documents posted on or after this date."
    )
    posting_to: Annotated[date | None, ODataCondition("PostingDate", operator="le")] = Field(
        default=None, description="Only material documents posted on or before this date."
    )
    created_by: Annotated[SAPCode | None, ODataCondition("CreatedByUser")] = Field(
        default=None, description="SAP user who posted the material document."
    )
    reference_document: Annotated[str | None, ODataCondition("ReferenceDocument")] = Field(
        default=None, description="Reference document, e.g. a delivery note number."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each material document.")


# ---------------------------------------------------------------------------
# Maintenance order confirmations (API_MAINTORDERCONFIRMATION, OData V2)
# ---------------------------------------------------------------------------


class SAPMaintenanceOrderConfirmationModel(SAPODataCreateModel):
    """Data to confirm work on a maintenance order operation (API_MAINTORDERCONFIRMATION, OData V2).

    The confirmation number is assigned by SAP. A final confirmation (is_final=True)
    completes the operation.

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "MaintenanceOrder": "4000123",
                    "MaintenanceOrderOperation": "10",
                    "ActualWorkQuantity": 1.5,
                    "ActualWorkQuantityUnit": "H",
                    "IsFinalConfirmation": True,
                    "PostingDate": "2026-11-02",
                    "ConfirmationText": "Seal replaced",
                }
            ]
        }
    )

    order_id: SAPCode = Field(
        alias="MaintenanceOrder",
        description="Maintenance order number, e.g. '4000123'.",
        min_length=1,
        max_length=12,
    )
    operation: Numc4 = Field(
        alias="MaintenanceOrderOperation", description="Operation number (4 digits, padded), e.g. 10 -> '0010'."
    )
    sub_operation: SAPCode | None = Field(
        default=None,
        alias="MaintenanceOrderSubOperation",
        description="Sub-operation number - only to confirm a sub-operation.",
        max_length=4,
    )
    personnel_number: SAPCode | None = Field(
        default=None,
        alias="PersonnelNumber",
        description="Personnel number of the employee who did the work, e.g. '50000001'.",
        max_length=8,
    )
    actual_work: SAPDecimal | None = Field(
        default=None,
        alias="ActualWorkQuantity",
        description="Actual work performed in `actual_work_unit`, e.g. 1.5.",
        ge=0,
        decimal_places=3,
    )
    actual_work_unit: SAPCode | None = Field(
        default=None,
        alias="ActualWorkQuantityUnit",
        description="Unit of the actual work (internal SAP unit code), e.g. 'H' (hours), 'MIN'.",
        max_length=3,
    )
    actual_duration: SAPDecimal | None = Field(
        default=None,
        alias="ActualDuration",
        description="Actual duration of the operation in `actual_duration_unit`.",
        ge=0,
        decimal_places=3,
    )
    actual_duration_unit: SAPCode | None = Field(
        default=None,
        alias="ActualDurationUnit",
        description="Unit of the actual duration (internal SAP unit code), e.g. 'H'.",
        max_length=3,
    )
    start_date: ODataV2Date = Field(
        default=None,
        alias="OperationConfirmedStartDate",
        description="Date the work started, e.g. '2026-11-01'.",
    )
    start_time: ODataV2Time = Field(
        default=None,
        alias="OperationConfirmedStartTime",
        description="Time the work started, Time (HH:MM:SS), e.g. '08:30:00'.",
    )
    end_date: ODataV2Date = Field(
        default=None,
        alias="OperationConfirmedEndDate",
        description="Date the work ended, e.g. '2026-11-01'.",
    )
    end_time: ODataV2Time = Field(
        default=None,
        alias="OperationConfirmedEndTime",
        description="Time the work ended, Time (HH:MM:SS), e.g. '08:30:00'.",
    )
    is_final: bool | None = Field(
        default=None,
        alias="IsFinalConfirmation",
        description="True for a final confirmation (completes the operation), false for a partial confirmation.",
    )
    no_remaining_work: bool | None = Field(
        default=None,
        alias="NoFurtherWorkQuantityIsExpd",
        description="True if no further work is expected for the operation.",
    )
    remaining_work: SAPDecimal | None = Field(
        default=None,
        alias="RemainingWorkQuantity",
        description="Expected remaining work in `remaining_work_unit`.",
        ge=0,
        decimal_places=3,
    )
    remaining_work_unit: SAPCode | None = Field(
        default=None,
        alias="RemainingWorkQuantityUnit",
        description="Unit of the remaining work (internal SAP unit code), e.g. 'H'.",
        max_length=3,
    )
    posting_date: ODataV2Date = Field(
        default=None,
        alias="PostingDate",
        description="Posting date, e.g. '2026-11-01'. Defaults to today.",
    )
    activity_type: SAPCode | None = Field(
        default=None,
        alias="ActivityType",
        description="Activity type for cost allocation. Defaults to the activity type of the operation - system specific; copy from an existing document if unsure.",
        max_length=6,
    )
    clear_open_reservations: bool | None = Field(
        default=None,
        alias="OpenReservationsIsCleared",
        description="True to clear open component reservations of the operation (with a final confirmation).",
    )
    text: str | None = Field(
        default=None,
        alias="ConfirmationText",
        description="Confirmation text, e.g. 'Seal replaced'.",
        max_length=40,
    )
    variance_reason: SAPCode | None = Field(
        default=None,
        alias="VarianceReasonCode",
        description="Reason for a variance - system specific; copy from an existing document if unsure.",
        max_length=4,
    )


class SAPMaintenanceOrderConfirmationResponseModel(SAPODataModel):
    """A maintenance order confirmation as returned by SAP (API_MAINTORDERCONFIRMATION, OData V2)."""

    confirmation_id: str = Field(
        alias="MaintOrderConf", description="Confirmation number (assigned by SAP). Part of the key."
    )
    counter: str = Field(alias="MaintOrderConfCntrValue", description="Confirmation counter. Part of the key.")
    order_id: str | None = Field(
        default=None, alias="MaintenanceOrder", description="Maintenance order number; see get_maintenance_order()."
    )
    operation: str | None = Field(
        default=None, alias="MaintenanceOrderOperation", description="Operation number (4 digits), e.g. '0010'."
    )
    sub_operation: str | None = Field(
        default=None, alias="MaintenanceOrderSubOperation", description="Sub-operation number."
    )
    personnel_number: str | None = Field(
        default=None, alias="PersonnelNumber", description="Personnel number of the employee who did the work."
    )
    actual_work: SAPDecimal | None = Field(
        default=None, alias="ActualWorkQuantity", description="Actual work performed."
    )
    actual_work_unit: str | None = Field(
        default=None,
        alias="ActualWorkQuantityUnit",
        description="Unit of the actual work (internal SAP unit code), e.g. 'H'.",
    )
    start_date: ODataDate = Field(
        default=None, alias="OperationConfirmedStartDate", description="Date the work started."
    )
    start_time: ODataTime = Field(
        default=None, alias="OperationConfirmedStartTime", description="Time the work started."
    )
    end_date: ODataDate = Field(default=None, alias="OperationConfirmedEndDate", description="Date the work ended.")
    end_time: ODataTime = Field(default=None, alias="OperationConfirmedEndTime", description="Time the work ended.")
    is_final: SAPFlag = Field(default=None, alias="IsFinalConfirmation", description="True for a final confirmation.")
    posting_date: ODataDate = Field(default=None, alias="PostingDate", description="Posting date.")
    text: str | None = Field(default=None, alias="ConfirmationText", description="Confirmation text.")
    material_document: str | None = Field(
        default=None,
        alias="MaterialDocument",
        description="Material document posted with the confirmation (goods movements), if any.",
    )

    # ---------------------------------------------------------------------------
    # Maintenance plans (API_MAINTENANCEPLAN, OData V2)
    # ---------------------------------------------------------------------------
    forecasted_end_date: ODataDate = Field(
        default=None,
        alias="ActyConfFcstdEndDate",
        description="Forecasted finish date of the operation, entered with the confirmation.",
    )
    forecasted_end_time: ODataTime = Field(
        default=None,
        alias="ActyConfFcstdEndTime",
        description="Forecasted finish time of the operation, entered with the confirmation.",
    )
    remaining_work: SAPDecimal | None = Field(
        default=None,
        alias="RemainingWorkQuantity",
        description="Remaining work that is still expected for the operation.",
    )
    remaining_work_unit: str | None = Field(
        default=None, alias="RemainingWorkQuantityUnit", description="Unit of the remaining work, e.g. 'H' (hours)."
    )
    no_remaining_work: SAPFlag = Field(
        default=None,
        alias="NoFurtherWorkQuantityIsExpd",
        description="True if no further work is expected for the operation (no remaining work).",
    )


class SAPMaintenanceOrderConfirmationQueryModel(SAPODataQueryModel):
    """Search criteria for SAP maintenance order confirmations (API_MAINTORDERCONFIRMATION)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "confirmation_id": "MaintOrderConf {direction}",
        "posting_date": "PostingDate {direction}",
    }
    sort_by: Literal["confirmation_id", "posting_date"] = Field(
        default="confirmation_id", description="Sort criterion."
    )
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    order_id: Annotated[SAPCode | None, ODataCondition("MaintenanceOrder")] = Field(
        default=None, description="Maintenance order the confirmations belong to, e.g. '4000340'."
    )
    operation: Annotated[SAPCode | None, ODataCondition("MaintenanceOrderOperation")] = Field(
        default=None, description="Operation number of the order, e.g. '0010'."
    )
    personnel_number: Annotated[SAPCode | None, ODataCondition("PersonnelNumber")] = Field(
        default=None, description="Personnel number of the employee who did the work."
    )
    is_final: Annotated[bool | None, ODataCondition("IsFinalConfirmation", kind="flag")] = Field(
        default=None, description="True = only final confirmations, False = only partial confirmations."
    )
    posting_from: Annotated[date | None, ODataCondition("PostingDate", operator="ge")] = Field(
        default=None, description="Only confirmations posted on or after this date."
    )
    posting_to: Annotated[date | None, ODataCondition("PostingDate", operator="le")] = Field(
        default=None, description="Only confirmations posted on or before this date."
    )


class SAPMaintenancePlanCycleModel(SAPODataCreateModel):
    """A cycle of a maintenance plan, e.g. every 3 months or every 500 operating hours."""

    interval: SAPDecimal = Field(
        alias="MaintPlanCycRcrrcIntervalQty",
        description="Cycle length (greater than 0), e.g. 3 (with `interval_unit` 'MON' = every 3 months).",
        gt=0,
    )
    interval_unit: SAPCode = Field(
        alias="MaintPlanCycRcrrcIntervalUnit",
        description="Unit of the cycle (internal SAP unit code), e.g. 'MON' (months), 'WK' (weeks), 'D' (days), 'H' (operating hours).",
        min_length=1,
        max_length=3,
    )
    description: str | None = Field(
        default=None,
        alias="MaintPlanCycleDesc",
        description="Text of the cycle, e.g. 'Quarterly'.",
        max_length=40,
    )
    measuring_point: SAPCode | None = Field(
        default=None,
        alias="MeasuringPoint",
        description="Measuring point (counter, max. 12 characters) - only for performance-based cycles, e.g. operating hours.",
        max_length=12,
    )
    start_offset: SAPDecimal | None = Field(
        default=None,
        alias="MaintPlanCycleStartOffsetValue",
        description="Offset of the first call (in `interval_unit`).",
        ge=0,
    )


class SAPMaintenancePlanItemModel(SAPODataCreateModel):
    """A maintenance item of a maintenance plan - the object to maintain and how (task list, order type)."""

    description: str = Field(
        alias="MaintenanceItemDescription",
        description="Text of the maintenance item, e.g. 'Inspect pump'.",
        min_length=1,
        max_length=40,
    )
    equipment: SAPCode | None = Field(
        default=None,
        alias="Equipment",
        description="Equipment to maintain, e.g. '210100001'. Give this or `functional_location`.",
        max_length=18,
    )
    functional_location: str | None = Field(
        default=None,
        alias="FunctionalLocation",
        description="Internal functional location ID - not the label shown in the UI. Give this or `equipment`.",
        max_length=30,
    )
    task_list_type: SAPCode | None = Field(
        default=None,
        alias="TaskListType",
        description="Task list type: 'A' general task list, 'E' equipment task list, 'T' functional location task list.",
        max_length=1,
    )
    task_list_group: SAPCode | None = Field(
        default=None,
        alias="TaskListGroup",
        description="Task list group describing the work to do - system specific; copy from an existing document if unsure.",
        max_length=8,
    )
    task_list_group_counter: SAPCode | None = Field(
        default=None,
        alias="TaskListGroupCounter",
        description="Task list group counter, e.g. '1'.",
        max_length=2,
    )
    planning_plant: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant, e.g. '1010'.",
        max_length=4,
    )
    planner_group: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlannerGroup",
        description="Maintenance planner group - system specific; copy from an existing document if unsure.",
        max_length=3,
    )
    order_type: SAPCode | None = Field(
        default=None,
        alias="MaintenanceOrderType",
        description="Order type of the generated maintenance orders, e.g. 'PM03' or 'YA03' - system specific; copy from an existing document if unsure.",
        max_length=4,
    )
    notification_type: SAPCode | None = Field(
        default=None,
        alias="NotificationType",
        description="Notification type of generated notifications, e.g. 'M1' - system specific; copy from an existing document if unsure.",
        max_length=2,
    )
    activity_type: SAPCode | None = Field(
        default=None,
        alias="MaintenanceActivityType",
        description="Maintenance activity type, e.g. '001' (inspection) - system specific; copy from an existing document if unsure.",
        max_length=3,
    )
    main_work_center: SAPCode | None = Field(
        default=None,
        alias="MainWorkCenter",
        description="Main work center of the generated orders, e.g. 'RES-0100'.",
        max_length=8,
    )
    main_work_center_plant: SAPCode | None = Field(
        default=None,
        alias="MainWorkCenterPlant",
        description="Plant of the main work center, e.g. '1010'.",
        max_length=4,
    )
    priority: SAPCode | None = Field(
        default=None,
        alias="MaintPriority",
        description="Maintenance priority of the generated orders, e.g. '3' - system specific; copy from an existing document if unsure.",
        max_length=1,
    )


class SAPMaintenancePlanModel(SAPODataCreateModel):
    """Data to create an SAP maintenance plan (API_MAINTENANCEPLAN, OData V2).

    A single cycle plan has one or more cycles; a strategy plan references a
    maintenance strategy instead. The plan number is assigned by SAP. After the
    creation, scheduling has to be started (see change_maintenance_plan_status()).

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "MaintenancePlanDesc": "Quarterly pump inspection",
                    "MaintenancePlanCategory": "PM",
                    "to_MaintenanceCycle": [
                        {"MaintPlanCycRcrrcIntervalQty": 3, "MaintPlanCycRcrrcIntervalUnit": "MON"}
                    ],
                    "to_Item": [
                        {
                            "MaintenanceItemDescription": "Inspect pump",
                            "Equipment": "210100001",
                            "MaintenancePlanningPlant": "1010",
                            "MaintenanceOrderType": "YA03",
                            "MainWorkCenter": "RES-0100",
                            "MainWorkCenterPlant": "1010",
                        }
                    ],
                }
            ]
        }
    )

    description: str = Field(
        alias="MaintenancePlanDesc",
        description="Text of the maintenance plan, e.g. 'Quarterly pump inspection'.",
        min_length=1,
        max_length=40,
    )
    category: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlanCategory",
        description="Maintenance plan category, e.g. 'PM' (maintenance order), 'SM' (service order) - system specific; copy from an existing document if unsure.",
        max_length=2,
    )
    strategy: SAPCode | None = Field(
        default=None,
        alias="MaintenanceStrategy",
        description="Maintenance strategy for strategy plans, e.g. 'A'. Omit for single cycle plans (use `cycles`) - system specific; copy from an existing document if unsure.",
        max_length=6,
    )
    call_horizon_percent: SAPDecimal | None = Field(
        default=None,
        alias="CallHorizonPercent",
        description="Call horizon in percent (0-100): when within the cycle the order is generated, e.g. 80.",
        ge=0,
        le=100,
    )
    scheduling_start_date: ODataV2Date = Field(
        default=None,
        alias="SchedulingStartDate",
        description="Start date for scheduling, e.g. '2026-11-01'.",
    )
    cycles: list[SAPMaintenancePlanCycleModel] = Field(
        default_factory=list,
        alias="to_MaintenanceCycle",
        description="Cycles of a single cycle plan (e.g. every 3 months). Leave empty for strategy plans.",
        exclude_if=is_empty,
    )
    items: list[SAPMaintenancePlanItemModel] = Field(
        default_factory=list,
        alias="to_Item",
        description="Maintenance items (objects to maintain and how).",
        exclude_if=is_empty,
    )


class SAPMaintenancePlanCycleResponseModel(SAPODataModel):
    """A cycle of a maintenance plan as returned by SAP (API_MAINTENANCEPLAN)."""

    plan_id: str = Field(
        alias="MaintenancePlan",
        description="Maintenance plan that generated the order (preventive maintenance); see get_maintenance_plan().",
    )
    cycle: str = Field(alias="MaintenancePlanCycle", description="Cycle number within the plan.")
    interval: SAPDecimal | None = Field(
        default=None, alias="MaintPlanCycRcrrcIntervalQty", description="Cycle length in `interval_unit`."
    )
    interval_unit: str | None = Field(
        default=None,
        alias="MaintPlanCycRcrrcIntervalUnit",
        description="Unit of the cycle (internal SAP unit code), e.g. 'MON'.",
    )
    description: str | None = Field(default=None, alias="MaintPlanCycleDesc", description="Text of the cycle.")
    measuring_point: str | None = Field(
        default=None, alias="MeasuringPoint", description="Measuring point (counter) for performance-based cycles."
    )
    is_inactive: SAPFlag = Field(
        default=None, alias="MaintenancePlanCycleIsInactive", description="True if the cycle is inactive."
    )


class SAPMaintenancePlanItemResponseModel(SAPODataModel):
    """A maintenance item of a maintenance plan as returned by SAP (API_MAINTENANCEPLAN)."""

    item_id: str = Field(
        alias="MaintenanceItem", description="Maintenance item of the maintenance plan that generated the order."
    )
    plan_id: str | None = Field(
        default=None,
        alias="MaintenancePlan",
        description="Maintenance plan that generated the order (preventive maintenance); see get_maintenance_plan().",
    )
    description: str | None = Field(
        default=None, alias="MaintenanceItemDescription", description="Text of the maintenance item."
    )
    equipment: str | None = Field(
        default=None,
        alias="Equipment",
        description="Equipment - an individual technical object (e.g. a pump) that is maintained; see get_equipment().",
    )
    functional_location: str | None = Field(
        default=None,
        alias="FunctionalLocationLabelName",
        description="Functional location label as shown in the SAP UI, e.g. 'C1-B01-1'.",
    )
    task_list_type: str | None = Field(
        default=None,
        alias="TaskListType",
        description="Task list type: 'A' general, 'E' equipment, 'T' functional location task list.",
    )
    task_list_group: str | None = Field(default=None, alias="TaskListGroup", description="Task list group.")
    task_list_group_counter: str | None = Field(
        default=None, alias="TaskListGroupCounter", description="Task list group counter."
    )
    planning_plant: str | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant - the plant whose planner groups plan and schedule the maintenance work.",
    )
    order_type: str | None = Field(
        default=None, alias="MaintenanceOrderType", description="Order type of the generated maintenance orders."
    )
    main_work_center: str | None = Field(
        default=None,
        alias="MainWorkCenter",
        description="Main work center - responsible for executing the maintenance work; see get_work_center().",
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date on which the maintenance item was created."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None,
        alias="LastChangeDateTime",
        description="Timestamp of the last change of the maintenance item (timezone-aware).",
    )
    functional_location_id: str | None = Field(
        default=None,
        alias="FunctionalLocation",
        description="Functional location (internal ID) - a place in the technical structure where equipment is installed; see get_functional_location().",
    )


class SAPMaintenancePlanResponseModel(SAPODataModel):
    """A maintenance plan as returned by SAP (API_MAINTENANCEPLAN, OData V2).

    Attributes:
        cycles / items:
            None if they have not been requested ($expand), otherwise a (possibly empty) list.

    """

    plan_id: str = Field(
        alias="MaintenancePlan",
        description="Maintenance plan that generated the order (preventive maintenance); see get_maintenance_plan().",
    )
    description: str | None = Field(
        default=None, alias="MaintenancePlanDesc", description="Text of the maintenance plan."
    )
    category: str | None = Field(
        default=None, alias="MaintenancePlanCategory", description="Maintenance plan category, e.g. 'PM'."
    )
    strategy: str | None = Field(
        default=None, alias="MaintenanceStrategy", description="Maintenance strategy (empty for single cycle plans)."
    )
    system_status: str | None = Field(
        default=None,
        alias="MaintenancePlanSystemStatus",
        description="System status of the plan, e.g. active, inactive or marked for deletion.",
    )
    scheduling_start_date: ODataDate = Field(
        default=None, alias="SchedulingStartDate", description="Start date for scheduling."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    basic_start_date: ODataDate = Field(
        default=None,
        alias="BasicStartDate",
        description="Start date of the maintenance plan (cycle start for the scheduling).",
    )
    scheduling_start_time: ODataTime = Field(
        default=None,
        alias="SchedulingStartTime",
        description="Start time for the scheduling (see scheduling_start_date).",
    )
    scheduling_end_date: ODataDate = Field(
        default=None,
        alias="SchedulingEndDate",
        description="End date of the scheduling - no calls are planned after this date.",
    )
    cycles: Annotated[
        list[SAPMaintenancePlanCycleResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_MaintenanceCycle",
        description="Cycles. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    items: Annotated[
        list[SAPMaintenancePlanItemResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_Item",
        description="Maintenance items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPMaintenancePlanQueryModel(SAPODataQueryModel):
    """Search criteria for SAP maintenance plans (API_MAINTENANCEPLAN)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "plan_id": "MaintenancePlan {direction}",
        "created": "CreationDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_MaintenanceCycle,to_Item"
    sort_by: Literal["plan_id", "created"] = Field(default="plan_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    plan_ids: Annotated[list[SAPCode] | None, ODataCondition("MaintenancePlan")] = Field(
        default=None, description="Maintenance plan numbers."
    )
    description_contains: Annotated[str | None, ODataCondition("MaintenancePlanDesc", operator="contains")] = Field(
        default=None, description="Text contained in the plan description (case-sensitive)."
    )
    categories: Annotated[list[SAPCode] | None, ODataCondition("MaintenancePlanCategory")] = Field(
        default=None, description="Maintenance plan categories, e.g. ['PM']. System specific."
    )
    strategies: Annotated[list[SAPCode] | None, ODataCondition("MaintenanceStrategy")] = Field(
        default=None, description="Maintenance strategies of strategy plans. System specific."
    )
    created_from: Annotated[date | None, ODataCondition("CreationDate", operator="ge")] = Field(
        default=None, description="Only plans created on or after this date."
    )
    created_to: Annotated[date | None, ODataCondition("CreationDate", operator="le")] = Field(
        default=None, description="Only plans created on or before this date."
    )
    expand_items: bool = Field(default=False, description="Also return the cycles and items of each plan.")


# ---------------------------------------------------------------------------
# Planned orders (API_PLANNEDORDER, OData V4)
# ---------------------------------------------------------------------------


class SAPPlannedOrderModel(SAPODataCreateModel):
    """Data to create an SAP planned order (API_PLANNEDORDER, OData V4).

    Components and capacities are determined by SAP (bill of material and routing /
    production version). A planned order can be converted into a production order
    (see SAP.convert_planned_order()). The planned order number is assigned by SAP.

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "PlannedOrderType": "LA",
                    "Material": "FG126",
                    "MRPPlant": "1010",
                    "TotalQuantity": 10,
                    "PlndOrderPlannedStartDate": "2026-11-09",
                    "PlndOrderPlannedEndDate": "2026-11-16",
                }
            ]
        }
    )

    order_type: SAPCode = Field(
        alias="PlannedOrderType",
        description="Planned order type, e.g. 'LA' (stock order), 'KD' (customer order) - system specific; copy from an existing document if unsure.",
        min_length=1,
        max_length=4,
    )
    material: SAPCode = Field(
        alias="Material",
        description="Material (product) to produce or procure, e.g. 'FG126'.",
        min_length=1,
        max_length=40,
    )
    mrp_plant: SAPCode = Field(
        alias="MRPPlant", description="MRP (planning) plant, e.g. '1010'.", min_length=1, max_length=4
    )
    production_plant: SAPCode | None = Field(
        default=None,
        alias="ProductionPlant",
        description="Production plant, e.g. '1010'. Defaults to the MRP plant.",
        max_length=4,
    )
    mrp_area: SAPCode | None = Field(
        default=None,
        alias="MRPArea",
        description="MRP area. Defaults to the plant MRP area.",
        max_length=10,
    )
    production_version: SAPCode | None = Field(
        default=None,
        alias="ProductionVersion",
        description="Production version (BOM + routing), e.g. '0001'.",
        max_length=4,
    )
    storage_location: SAPCode | None = Field(
        default=None,
        alias="StorageLocation",
        description="Receiving storage location, e.g. '101A'.",
        max_length=4,
    )
    quantity: SAPDecimal = Field(
        alias="TotalQuantity",
        description="Total order quantity (greater than 0), e.g. 10.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="BaseUnit",
        description="Base unit of the material (internal SAP unit code), e.g. 'ST'.",
        max_length=3,
    )
    start_date: date | None = Field(
        default=None,
        alias="PlndOrderPlannedStartDate",
        description="Planned start date, e.g. '2026-11-01'.",
    )
    start_time: dtime | None = Field(
        default=None,
        alias="PlndOrderPlannedStartTime",
        description="Planned start time, Time (HH:MM:SS), e.g. '08:30:00'.",
    )
    end_date: date | None = Field(
        default=None,
        alias="PlndOrderPlannedEndDate",
        description="Planned end (finish) date, e.g. '2026-11-01'. Must not be before `start_date`.",
    )
    end_time: dtime | None = Field(
        default=None, alias="PlndOrderPlannedEndTime", description="Planned end time, Time (HH:MM:SS), e.g. '08:30:00'."
    )
    is_firm: bool | None = Field(
        default=None, alias="PlannedOrderIsFirm", description="True to firm the planned order (MRP will not change it)."
    )
    mrp_controller: SAPCode | None = Field(
        default=None,
        alias="MRPController",
        description="MRP controller, e.g. '001'. Defaults to the MRP controller of the material.",
        max_length=3,
    )
    production_supervisor: SAPCode | None = Field(
        default=None,
        alias="ProductionSupervisor",
        description="Production supervisor, e.g. '001'.",
        max_length=3,
    )
    long_text: str | None = Field(
        default=None, alias="PlannedOrderLongText", description="Long text of the planned order."
    )

    @model_validator(mode="after")
    def check_dates(self) -> Self:
        """Validate that the planned end date is not before the planned start date."""

        if self.start_date and self.end_date and self.end_date < self.start_date:
            message = "Planned end date -> {} is before planned start date -> {}".format(
                self.end_date,
                self.start_date,
            )
            raise ValueError(message)

        return self

    # end method definition


class SAPPlannedOrderResponseModel(SAPODataModel):
    """A planned order as returned by SAP (API_PLANNEDORDER, OData V4).

    Components and capacities are not modelled - they are available in model_extra
    if requested with $expand.

    """

    planned_order_id: str = Field(alias="PlannedOrder", description="Planned order number (assigned by SAP).")
    order_type: str | None = Field(
        default=None, alias="PlannedOrderType", description="Planned order type, e.g. 'LA' (stock order)."
    )
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    material_name: str | None = Field(default=None, alias="MaterialName", description="Description of the material.")
    mrp_plant: str | None = Field(
        default=None,
        alias="MRPPlant",
        description="Plant whose material requirements planning (MRP) plans the material.",
    )
    production_plant: str | None = Field(
        default=None, alias="ProductionPlant", description="Plant in which the material is produced; see get_plants()."
    )
    production_version: str | None = Field(
        default=None,
        alias="ProductionVersion",
        description="Production version - defines which bill of material and routing are used to produce the material; see get_production_version().",
    )
    quantity: SAPDecimal | None = Field(default=None, alias="TotalQuantity", description="Total order quantity.")
    unit: str | None = Field(
        default=None, alias="BaseUnit", description="Base unit of the material (internal SAP unit code)."
    )
    start_date: date | None = Field(default=None, alias="PlndOrderPlannedStartDate", description="Planned start date.")
    end_date: date | None = Field(
        default=None, alias="PlndOrderPlannedEndDate", description="Planned end (finish) date."
    )
    opening_date: date | None = Field(
        default=None,
        alias="PlannedOrderOpeningDate",
        description="Planned opening date (when the order should be converted).",
    )
    is_firm: SAPFlag = Field(
        default=None, alias="PlannedOrderIsFirm", description="True if the planned order is firmed."
    )
    is_convertible: SAPFlag = Field(
        default=None,
        alias="PlannedOrderIsConvertible",
        description="True if the planned order can be converted into a production order.",
    )
    mrp_controller: str | None = Field(
        default=None,
        alias="MRPController",
        description="MRP controller - the person or group responsible for planning the material.",
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="PlannedOrderLastChangeDateTime", description="Timestamp of the last change."
    )

    # ---------------------------------------------------------------------------
    # Production orders (API_PRODUCTION_ORDER_2_SRV, OData V2)
    # ---------------------------------------------------------------------------
    start_time: ODataTime = Field(
        default=None, alias="PlndOrderPlannedStartTime", description="Planned start time (see start_date)."
    )
    end_time: ODataTime = Field(
        default=None, alias="PlndOrderPlannedEndTime", description="Planned end (finish) time (see end_date)."
    )
    production_start_date: ODataDate = Field(
        default=None, alias="ProductionStartDate", description="Start date of the production (from the scheduling)."
    )
    production_end_date: ODataDate = Field(
        default=None, alias="ProductionEndDate", description="End date of the production (from the scheduling)."
    )
    scheduled_start_date: ODataDate = Field(
        default=None, alias="ScheduledBasicStartDate", description="Scheduled basic start date."
    )
    scheduled_start_time: ODataTime = Field(
        default=None, alias="ScheduledBasicStartTime", description="Scheduled basic start time."
    )
    scheduled_end_date: ODataDate = Field(
        default=None, alias="ScheduledBasicEndDate", description="Scheduled basic end date."
    )
    scheduled_end_time: ODataTime = Field(
        default=None, alias="ScheduledBasicEndTime", description="Scheduled basic end time."
    )
    last_scheduled_date: ODataDate = Field(
        default=None, alias="LastScheduledDate", description="Date on which the planned order was last scheduled."
    )
    storage_location: str | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location within the plant where the material is stored; see get_storage_locations().",
    )


class SAPPlannedOrderQueryModel(SAPODataQueryModel):
    """Search criteria for SAP planned orders (API_PLANNEDORDER, OData V4)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "planned_order_id": "PlannedOrder {direction}",
        "start_date": "PlndOrderPlannedStartDate {direction}",
    }
    sort_by: Literal["planned_order_id", "start_date"] = Field(
        default="planned_order_id", description="Sort criterion."
    )
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    planned_order_ids: Annotated[list[SAPCode] | None, ODataCondition("PlannedOrder")] = Field(
        default=None, description="Planned order numbers, e.g. ['1234']."
    )
    order_types: Annotated[list[SAPCode] | None, ODataCondition("PlannedOrderType")] = Field(
        default=None, description="Planned order types, e.g. ['LA']. System specific."
    )
    material: Annotated[SAPCode | None, ODataCondition("Material")] = Field(
        default=None, description="Material (product) to be produced or procured."
    )
    mrp_plant: Annotated[SAPCode | None, ODataCondition("MRPPlant")] = Field(
        default=None, description="MRP plant, e.g. '1010'."
    )
    production_plant: Annotated[SAPCode | None, ODataCondition("ProductionPlant")] = Field(
        default=None, description="Production plant, e.g. '1010'."
    )
    mrp_controller: Annotated[SAPCode | None, ODataCondition("MRPController")] = Field(
        default=None, description="MRP controller responsible for the planned order."
    )
    is_firm: Annotated[bool | None, ODataCondition("PlannedOrderIsFirm", kind="flag")] = Field(
        default=None, description="True = only firmed planned orders, False = only planned orders MRP may change."
    )
    start_from: Annotated[date | None, ODataCondition("PlndOrderPlannedStartDate", operator="ge")] = Field(
        default=None, description="Only planned orders starting on or after this date."
    )
    start_to: Annotated[date | None, ODataCondition("PlndOrderPlannedStartDate", operator="le")] = Field(
        default=None, description="Only planned orders starting on or before this date."
    )


class SAPProductionOrderModel(SAPODataCreateModel):
    """Data to create an SAP production order (API_PRODUCTION_ORDER_2_SRV, OData V2).

    Creates the header of a production order - operations and components are
    determined by SAP (routing / production version and bill of material). The
    production order number is assigned by SAP.

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "ManufacturingOrderType": "PP01",
                    "Material": "FG126",
                    "ProductionPlant": "1010",
                    "TotalQuantity": 10,
                    "MfgOrderPlannedStartDate": "2026-11-09",
                    "MfgOrderPlannedEndDate": "2026-11-16",
                }
            ]
        }
    )

    order_type: SAPCode = Field(
        alias="ManufacturingOrderType",
        description="Production order type, e.g. 'PP01' (standard production order) - system specific; copy from an existing document if unsure.",
        min_length=1,
        max_length=4,
    )
    material: SAPCode = Field(
        alias="Material",
        description="Material (product) to produce, e.g. 'FG126'.",
        min_length=1,
        max_length=40,
    )
    plant: SAPCode = Field(
        alias="ProductionPlant", description="Production plant, e.g. '1010'.", min_length=1, max_length=4
    )
    quantity: SAPDecimal = Field(
        alias="TotalQuantity",
        description="Total order quantity (greater than 0), e.g. 10.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="ProductionUnit",
        description="Production unit (internal SAP unit code), e.g. 'ST'. Defaults to the base unit of the material.",
        max_length=3,
    )
    production_version: SAPCode | None = Field(
        default=None,
        alias="ProductionVersion",
        description="Production version (BOM + routing), e.g. '0001'.",
        max_length=4,
    )
    storage_location: SAPCode | None = Field(
        default=None,
        alias="StorageLocation",
        description="Receiving storage location, e.g. '101A'.",
        max_length=4,
    )
    planned_start_date: ODataV2Date = Field(
        default=None,
        alias="MfgOrderPlannedStartDate",
        description="Planned (basic) start date, e.g. '2026-11-01'.",
    )
    planned_start_time: ODataV2Time = Field(
        default=None,
        alias="MfgOrderPlannedStartTime",
        description="Planned (basic) start time, Time (HH:MM:SS), e.g. '08:30:00'.",
    )
    planned_end_date: ODataV2Date = Field(
        default=None,
        alias="MfgOrderPlannedEndDate",
        description="Planned (basic) end date, e.g. '2026-11-01'. Must not be before `planned_start_date`.",
    )
    planned_end_time: ODataV2Time = Field(
        default=None,
        alias="MfgOrderPlannedEndTime",
        description="Planned (basic) end time, Time (HH:MM:SS), e.g. '08:30:00'.",
    )
    scheduling_type: SAPCode | None = Field(
        default=None,
        alias="BasicSchedulingType",
        description="Basic scheduling type, e.g. '1' (forwards) or '2' (backwards).",
        max_length=1,
    )
    mrp_controller: SAPCode | None = Field(
        default=None, alias="MRPController", description="MRP controller, e.g. '001'.", max_length=3
    )
    production_supervisor: SAPCode | None = Field(
        default=None,
        alias="ProductionSupervisor",
        description="Production supervisor, e.g. '001'.",
        max_length=3,
    )

    @model_validator(mode="after")
    def check_dates(self) -> Self:
        """Validate that the planned end date is not before the planned start date."""

        if self.planned_start_date and self.planned_end_date and self.planned_end_date < self.planned_start_date:
            message = "Planned end date -> {} is before planned start date -> {}".format(
                self.planned_end_date,
                self.planned_start_date,
            )
            raise ValueError(message)

        return self

    # end method definition


class SAPProductionOrderOperationResponseModel(SAPODataModel):
    """An operation of a production order as returned by SAP (API_PRODUCTION_ORDER_2_SRV)."""

    order_id: str | None = Field(default=None, alias="ManufacturingOrder", description="Production order number.")
    operation: str | None = Field(
        default=None, alias="ManufacturingOrderOperation", description="Operation number, e.g. '0010'."
    )
    sequence: str | None = Field(
        default=None,
        alias="ManufacturingOrderSequence",
        description="Sequence of the operation (0 = standard sequence).",
    )
    text: str | None = Field(default=None, alias="MfgOrderOperationText", description="Short text of the operation.")
    work_center: str | None = Field(
        default=None,
        alias="WorkCenter",
        description="Work center - the people or machines (with capacity) that perform the work; see get_work_center().",
    )
    plant: str | None = Field(
        default=None, alias="ProductionPlant", description="Plant in which the material is produced; see get_plants()."
    )
    control_profile: str | None = Field(
        default=None, alias="OperationControlProfile", description="Operation control key, e.g. 'PP01'."
    )
    planned_quantity: SAPDecimal | None = Field(
        default=None, alias="OpPlannedTotalQuantity", description="Planned total quantity of the operation."
    )
    confirmed_yield: SAPDecimal | None = Field(
        default=None, alias="OpTotalConfirmedYieldQty", description="Confirmed yield (good quantity) of the operation."
    )
    unit: str | None = Field(
        default=None, alias="OperationUnit", description="Unit of the operation quantities (internal SAP unit code)."
    )
    is_released: SAPFlag = Field(
        default=None, alias="OperationIsReleased", description="True if the operation is released."
    )
    is_confirmed: SAPFlag = Field(
        default=None, alias="OperationIsConfirmed", description="True if the operation is (finally) confirmed."
    )
    earliest_scheduled_start_date: ODataDate = Field(
        default=None,
        alias="OpErlstSchedldExecStrtDte",
        description="Earliest scheduled start date of the operation execution.",
    )
    earliest_scheduled_start_time: ODataTime = Field(
        default=None,
        alias="OpErlstSchedldExecStrtTme",
        description="Earliest scheduled start time of the operation execution.",
    )
    earliest_scheduled_end_date: ODataDate = Field(
        default=None,
        alias="OpErlstSchedldExecEndDte",
        description="Earliest scheduled finish date of the operation execution.",
    )
    earliest_scheduled_end_time: ODataTime = Field(
        default=None,
        alias="OpErlstSchedldExecEndTme",
        description="Earliest scheduled finish time of the operation execution.",
    )
    actual_start_date: ODataDate = Field(
        default=None,
        alias="OpActualExecutionStartDate",
        description="Confirmed (actual) start date of the operation execution.",
    )
    actual_start_time: ODataTime = Field(
        default=None,
        alias="OpActualExecutionStartTime",
        description="Confirmed (actual) start time of the operation execution.",
    )
    actual_end_date: ODataDate = Field(
        default=None,
        alias="OpActualExecutionEndDate",
        description="Confirmed (actual) finish date of the operation execution.",
    )
    actual_end_time: ODataTime = Field(
        default=None,
        alias="OpActualExecutionEndTime",
        description="Confirmed (actual) finish time of the operation execution.",
    )


class SAPProductionOrderStatusResponseModel(SAPODataModel):
    """An active status of a production order as returned by SAP (API_PRODUCTION_ORDER_2_SRV)."""

    order_id: str = Field(alias="ManufacturingOrder", description="Production order number.")
    status_code: str = Field(alias="StatusCode", description="Internal status code, e.g. 'I0002' (released).")
    short_name: str | None = Field(
        default=None, alias="StatusShortName", description="Status abbreviation, e.g. 'REL', 'TECO', 'CNF'."
    )
    name: str | None = Field(default=None, alias="StatusName", description="Status name, e.g. 'Released'.")


class SAPProductionOrderResponseModel(SAPODataModel):
    """A production order as returned by SAP (API_PRODUCTION_ORDER_2_SRV, OData V2).

    Attributes:
        operations / statuses:
            None if they have not been requested ($expand), otherwise a (possibly empty) list.

    """

    order_id: str = Field(
        alias="ManufacturingOrder", description="Production order number (assigned by SAP), e.g. '1000001'."
    )
    order_type: str | None = Field(
        default=None, alias="ManufacturingOrderType", description="Production order type, e.g. 'PP01'."
    )
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    plant: str | None = Field(
        default=None, alias="ProductionPlant", description="Plant in which the material is produced; see get_plants()."
    )
    production_version: str | None = Field(
        default=None,
        alias="ProductionVersion",
        description="Production version - defines which bill of material and routing are used to produce the material; see get_production_version().",
    )
    planned_order: str | None = Field(
        default=None, alias="PlannedOrder", description="Planned order the production order was converted from, if any."
    )
    quantity: SAPDecimal | None = Field(default=None, alias="TotalQuantity", description="Total order quantity.")
    unit: str | None = Field(
        default=None, alias="ProductionUnit", description="Production unit (internal SAP unit code)."
    )
    confirmed_yield: SAPDecimal | None = Field(
        default=None, alias="MfgOrderConfirmedYieldQty", description="Confirmed yield (good quantity) of the order."
    )
    planned_start_date: ODataDate = Field(
        default=None, alias="MfgOrderPlannedStartDate", description="Planned (basic) start date."
    )
    planned_end_date: ODataDate = Field(
        default=None, alias="MfgOrderPlannedEndDate", description="Planned (basic) end date."
    )
    scheduled_start_date: ODataDate = Field(
        default=None, alias="MfgOrderScheduledStartDate", description="Scheduled start date (result of scheduling)."
    )
    scheduled_end_date: ODataDate = Field(
        default=None, alias="MfgOrderScheduledEndDate", description="Scheduled end date (result of scheduling)."
    )
    creation_date: ODataDate = Field(
        default=None, alias="MfgOrderCreationDate", description="Date the order was created."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    is_released: SAPFlag = Field(
        default=None, alias="OrderIsReleased", description="True if the order is released (status REL)."
    )
    is_technically_completed: SAPFlag = Field(
        default=None,
        alias="OrderIsTechnicallyCompleted",
        description="True if the order is technically completed (status TECO).",
    )
    is_closed: SAPFlag = Field(
        default=None, alias="OrderIsClosed", description="True if the order is closed (status CLSD)."
    )
    is_marked_for_deletion: SAPFlag = Field(
        default=None,
        alias="OrderIsMarkedForDeletion",
        description="True if the order has the deletion flag (status DLFL).",
    )
    is_locked: SAPFlag = Field(
        default=None, alias="OrderIsLocked", description="True if the order is locked (status LKD)."
    )
    creation_time: ODataTime = Field(
        default=None, alias="MfgOrderCreationTime", description="Time when the order was created (see creation_date)."
    )
    planned_start_time: ODataTime = Field(
        default=None, alias="MfgOrderPlannedStartTime", description="Planned start time (see planned_start_date)."
    )
    planned_end_time: ODataTime = Field(
        default=None, alias="MfgOrderPlannedEndTime", description="Planned end (finish) time (see planned_end_date)."
    )
    scheduled_start_time: ODataTime = Field(
        default=None, alias="MfgOrderScheduledStartTime", description="Scheduled start time (see scheduled_start_date)."
    )
    scheduled_end_time: ODataTime = Field(
        default=None,
        alias="MfgOrderScheduledEndTime",
        description="Scheduled end (finish) time (see scheduled_end_date).",
    )
    actual_release_date: ODataDate = Field(
        default=None, alias="MfgOrderActualReleaseDate", description="Date on which the order was actually released."
    )
    mrp_controller: str | None = Field(
        default=None,
        alias="MRPController",
        description="MRP controller - the person or group responsible for planning the material.",
    )
    storage_location: str | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location within the plant where the material is stored; see get_storage_locations().",
    )
    sales_order: str | None = Field(
        default=None,
        alias="SalesOrder",
        description="Sales order the record belongs to (e.g. make-to-order production); see get_sales_order().",
    )
    long_text: str | None = Field(
        default=None, alias="OrderLongText", description="Long text (note) of the production order."
    )
    operations: Annotated[
        list[SAPProductionOrderOperationResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_ProductionOrderOperation",
        description="Operations. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    statuses: Annotated[
        list[SAPProductionOrderStatusResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_ProductionOrderStatus",
        description="Active statuses. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPProductionOrderQueryModel(SAPODataQueryModel):
    """Search criteria for SAP production orders (API_PRODUCTION_ORDER_2_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "order_id": "ManufacturingOrder {direction}",
        "planned_start": "MfgOrderPlannedStartDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_ProductionOrderOperation,to_ProductionOrderStatus"
    sort_by: Literal["order_id", "planned_start"] = Field(default="order_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    order_ids: Annotated[list[SAPCode] | None, ODataCondition("ManufacturingOrder")] = Field(
        default=None, description="Production order numbers, e.g. ['1000123']."
    )
    order_types: Annotated[list[SAPCode] | None, ODataCondition("ManufacturingOrderType")] = Field(
        default=None, description="Production order types, e.g. ['YBM1']. System specific."
    )
    material: Annotated[SAPCode | None, ODataCondition("Material")] = Field(
        default=None, description="Material (product) produced by the order."
    )
    plant: Annotated[SAPCode | None, ODataCondition("ProductionPlant")] = Field(
        default=None, description="Production plant, e.g. '1010'."
    )
    planned_order: Annotated[SAPCode | None, ODataCondition("PlannedOrder")] = Field(
        default=None, description="Planned order the production order was converted from."
    )
    mrp_controller: Annotated[SAPCode | None, ODataCondition("MRPController")] = Field(
        default=None, description="MRP controller responsible for the order."
    )
    is_released: Annotated[bool | None, ODataCondition("OrderIsReleased", kind="flag")] = Field(
        default=None, description="True = only released orders, False = only orders not released yet."
    )
    is_technically_completed: Annotated[bool | None, ODataCondition("OrderIsTechnicallyCompleted", kind="flag")] = (
        Field(
            default=None,
            description="True = only technically completed orders, False = only orders not technically completed.",
        )
    )
    is_closed: Annotated[bool | None, ODataCondition("OrderIsClosed", kind="flag")] = Field(
        default=None, description="True = only closed orders, False = only orders not closed."
    )
    planned_start_from: Annotated[date | None, ODataCondition("MfgOrderPlannedStartDate", operator="ge")] = Field(
        default=None, description="Only orders with planned start on or after this date."
    )
    planned_start_to: Annotated[date | None, ODataCondition("MfgOrderPlannedStartDate", operator="le")] = Field(
        default=None, description="Only orders with planned start on or before this date."
    )
    expand_items: bool = Field(default=False, description="Also return the operations and status of each order.")


# ---------------------------------------------------------------------------
# Master data (read only)
# ---------------------------------------------------------------------------


class SAPPlantResponseModel(SAPODataModel):
    """A plant as returned by SAP (API_PLANT_2, OData V4)."""

    plant_id: str = Field(
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    name: str | None = Field(default=None, alias="PlantName", description="Name of the plant.")
    valuation_area: str | None = Field(
        default=None, alias="ValuationArea", description="Valuation area (usually the plant)."
    )
    customer: str | None = Field(
        default=None, alias="PlantCustomer", description="Customer number of the plant (for stock transfers)."
    )
    supplier: str | None = Field(
        default=None, alias="PlantSupplier", description="Supplier number of the plant (for stock transfers)."
    )
    factory_calendar: str | None = Field(
        default=None, alias="FactoryCalendar", description="Factory calendar ID (working days)."
    )
    purchasing_organization: str | None = Field(
        default=None, alias="DefaultPurchasingOrganization", description="Default purchasing organization of the plant."
    )
    sales_organization: str | None = Field(
        default=None,
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    distribution_channel: str | None = Field(
        default=None,
        alias="DistributionChannel",
        description="Distribution channel, e.g. '10' (direct sales). Sales organization + distribution channel + division form the sales area.",
    )
    division: str | None = Field(
        default=None, alias="Division", description="Division (product line) - part of the sales area."
    )
    category: str | None = Field(
        default=None,
        alias="PlantCategory",
        description="Plant category: empty = plant, 'B' = store, 'A' = distribution center.",
    )
    language: str | None = Field(default=None, alias="Language", description="Language key of the plant.")


class SAPPlantQueryModel(SAPODataQueryModel):
    """Search criteria for SAP plants (API_PLANT_2, OData V4)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"plant": "Plant {direction}"}
    sort_by: Literal["plant"] = Field(default="plant", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    plant_ids: Annotated[list[SAPCode] | None, ODataCondition("Plant")] = Field(
        default=None, description="Plant IDs, e.g. ['1010']."
    )
    name_contains: Annotated[str | None, ODataCondition("PlantName", operator="contains")] = Field(
        default=None, description="Text contained in the plant name (case-sensitive)."
    )
    sales_organization: Annotated[SAPCode | None, ODataCondition("SalesOrganization")] = Field(
        default=None, description="Sales organization of the plant."
    )
    valuation_area: Annotated[SAPCode | None, ODataCondition("ValuationArea")] = Field(
        default=None, description="Valuation area of the plant."
    )


class SAPStorageLocationResponseModel(SAPODataModel):
    """A storage location of a plant as returned by SAP (API_STORAGELOCATION_SRV, OData V2)."""

    plant: str = Field(
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    storage_location: str = Field(
        alias="StorageLocation",
        description="Storage location within the plant where the material is stored; see get_storage_locations().",
    )
    name: str | None = Field(default=None, alias="StorageLocationName", description="Name of the storage location.")
    sales_organization: str | None = Field(
        default=None,
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    distribution_channel: str | None = Field(
        default=None,
        alias="DistributionChannel",
        description="Distribution channel, e.g. '10' (direct sales). Sales organization + distribution channel + division form the sales area.",
    )
    division: str | None = Field(
        default=None, alias="Division", description="Division (product line) - part of the sales area."
    )


class SAPStorageLocationQueryModel(SAPODataQueryModel):
    """Search criteria for SAP storage locations (API_STORAGELOCATION_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"plant": "Plant {direction},StorageLocation {direction}"}
    sort_by: Literal["plant"] = Field(default="plant", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    plant: Annotated[SAPCode | None, ODataCondition("Plant")] = Field(
        default=None, description="Plant of the storage locations, e.g. '1010'."
    )
    storage_locations: Annotated[list[SAPCode] | None, ODataCondition("StorageLocation")] = Field(
        default=None, description="Storage location IDs, e.g. ['101A']."
    )
    name_contains: Annotated[str | None, ODataCondition("StorageLocationName", operator="contains")] = Field(
        default=None, description="Text contained in the storage location name (case-sensitive)."
    )


class SAPProductDescriptionResponseModel(SAPODataModel):
    """A (language dependent) description of a product as returned by SAP (API_PRODUCT_SRV)."""

    product_id: str = Field(alias="Product", description="Product (material) number.")
    language: str = Field(alias="Language", description="Language key of the description, e.g. 'EN'.")
    description: str | None = Field(
        default=None, alias="ProductDescription", description="Description of the product in this language."
    )


class SAPProductPlantResponseModel(SAPODataModel):
    """The plant specific data of a product as returned by SAP (API_PRODUCT_SRV).

    Provides plant dependent defaults for documents, e.g. the MRP controller
    for planned / production orders or the purchasing group for purchasing documents.

    """

    product_id: str = Field(alias="Product", description="Product (material) number.")
    plant: str = Field(
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    mrp_type: str | None = Field(
        default=None, alias="MRPType", description="MRP type, e.g. 'PD' (MRP), 'ND' (no planning)."
    )
    mrp_controller: str | None = Field(
        default=None, alias="MRPResponsible", description="MRP controller responsible for the product in the plant."
    )
    procurement_type: str | None = Field(
        default=None,
        alias="ProcurementType",
        description="Procurement type: 'E' in-house production, 'F' external procurement, 'X' both.",
    )
    purchasing_group: str | None = Field(
        default=None,
        alias="PurchasingGroup",
        description="Purchasing group - the buyer or group of buyers responsible for the document.",
    )
    profit_center: str | None = Field(
        default=None,
        alias="ProfitCenter",
        description="Profit center the values are reported on (internal profitability); see get_profit_center().",
    )
    abc_indicator: str | None = Field(
        default=None, alias="ABCIndicator", description="ABC indicator (importance), e.g. 'A'."
    )
    goods_receipt_duration: SAPDecimal | None = Field(
        default=None, alias="GoodsReceiptDuration", description="Goods receipt processing time in workdays."
    )
    base_unit: str | None = Field(
        default=None, alias="BaseUnit", description="Base unit of the product (internal SAP unit code)."
    )
    is_batch_managed: bool | None = Field(
        default=None,
        alias="IsBatchManagementRequired",
        description="True if the product is managed in batches in this plant.",
    )
    is_marked_for_deletion: bool | None = Field(
        default=None,
        alias="IsMarkedForDeletion",
        description="True if the product is marked for deletion in this plant.",
    )
    status_validity_date: ODataDate = Field(
        default=None,
        alias="ProfileValidityStartDate",
        description="Date from which the plant-specific material status is valid.",
    )
    production_storage_location: str | None = Field(
        default=None,
        alias="ProductionInvtryManagedLoc",
        description="Default storage location for production (goods issues / receipts of production orders).",
    )


class SAPProductResponseModel(SAPODataModel):
    """A product (material) as returned by SAP (API_PRODUCT_SRV, OData V2).

    Attributes:
        descriptions / plants:
            None if they have not been requested ($expand), otherwise a (possibly empty) list.

    """

    product_id: str = Field(alias="Product", description="Product (material) number, e.g. 'TG11'.")
    product_type: str | None = Field(
        default=None,
        alias="ProductType",
        description="Product type, e.g. 'FERT' (finished product), 'ROH' (raw material), 'HAWA' (trading good).",
    )
    product_group: str | None = Field(default=None, alias="ProductGroup", description="Product (material) group.")
    base_unit: str | None = Field(
        default=None, alias="BaseUnit", description="Base unit of measure (internal SAP unit code), e.g. 'ST'."
    )
    division: str | None = Field(
        default=None, alias="Division", description="Division (product line) - part of the sales area."
    )
    gross_weight: SAPDecimal | None = Field(
        default=None, alias="GrossWeight", description="Gross weight in `weight_unit`."
    )
    net_weight: SAPDecimal | None = Field(default=None, alias="NetWeight", description="Net weight in `weight_unit`.")
    weight_unit: str | None = Field(default=None, alias="WeightUnit", description="Unit of the weights, e.g. 'KG'.")
    old_id: str | None = Field(default=None, alias="ProductOldID", description="Old (legacy) product number.")
    is_marked_for_deletion: bool | None = Field(
        default=None, alias="IsMarkedForDeletion", description="True if the product is marked for deletion."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    validity_start_date: ODataDate = Field(
        default=None, alias="ValidityStartDate", description="Date from which the product master data is valid."
    )
    cross_plant_status_validity_date: ODataDate = Field(
        default=None,
        alias="CrossPlantStatusValidityDate",
        description="Date from which the cross-plant material status is valid.",
    )
    descriptions: Annotated[
        list[SAPProductDescriptionResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None, alias="to_Description", description="Descriptions per language. None if not requested ($expand)."
    )
    plants: Annotated[
        list[SAPProductPlantResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(default=None, alias="to_Plant", description="Plant specific data. None if not requested ($expand).")


class SAPProductQueryModel(SAPODataQueryModel):
    """Search criteria for SAP products / materials (API_PRODUCT_SRV). Descriptions cannot be searched."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"product": "Product {direction}"}
    EXPAND: ClassVar[str] = "to_Description,to_Plant"
    sort_by: Literal["product"] = Field(default="product", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    product_ids: Annotated[list[SAPCode] | None, ODataCondition("Product")] = Field(
        default=None, description="Product (material) IDs, e.g. ['TG11']."
    )
    id_contains: Annotated[str | None, ODataCondition("Product", operator="contains")] = Field(
        default=None, description="Text contained in the product ID, e.g. 'PUMP' (case-sensitive)."
    )
    product_types: Annotated[list[SAPCode] | None, ODataCondition("ProductType")] = Field(
        default=None, description="Product types, e.g. ['FERT'] (finished product), ['ROH'] (raw material)."
    )
    product_groups: Annotated[list[SAPCode] | None, ODataCondition("ProductGroup")] = Field(
        default=None, description="Product (material) groups."
    )
    is_marked_for_deletion: Annotated[bool | None, ODataCondition("IsMarkedForDeletion")] = Field(
        default=None, description="True = only products marked for deletion, False = only active products."
    )
    expand_items: bool = Field(
        default=False, description="Also return the descriptions and plant data of each product."
    )


class SAPProductionVersionResponseModel(SAPODataModel):
    """A production version (BOM + routing for a material in a plant) as returned by SAP (API_PRODUCTION_VERSION, OData V4)."""

    material: str = Field(alias="Material", description="Material (product) number; see get_products().")
    plant: str = Field(
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    production_version: str = Field(
        alias="ProductionVersion",
        description="Production version - defines which bill of material and routing are used to produce the material; see get_production_version().",
    )
    text: str | None = Field(default=None, alias="ProductionVersionText", description="Text of the production version.")
    material_name: str | None = Field(default=None, alias="MaterialName", description="Description of the material.")
    bom_usage: str | None = Field(
        default=None, alias="BillOfMaterialVariantUsage", description="BOM usage, e.g. '1' (production)."
    )
    bom_variant: str | None = Field(
        default=None, alias="BillOfMaterialVariant", description="Alternative BOM, e.g. '1'."
    )
    routing_type: str | None = Field(
        default=None, alias="BillOfOperationsType", description="Task list (routing) type, e.g. 'N' (routing)."
    )
    routing_group: str | None = Field(
        default=None, alias="BillOfOperationsGroup", description="Task list (routing) group."
    )
    routing_variant: str | None = Field(
        default=None, alias="BillOfOperationsVariant", description="Task list (routing) group counter."
    )
    validity_start_date: date | None = Field(
        default=None, alias="ValidityStartDate", description="Start of the validity period."
    )
    validity_end_date: date | None = Field(
        default=None, alias="ValidityEndDate", description="End of the validity period."
    )
    min_lot_size: SAPDecimal | None = Field(
        default=None, alias="MaterialMinLotSizeQuantity", description="Minimum lot size the version is valid for."
    )
    max_lot_size: SAPDecimal | None = Field(
        default=None, alias="MaterialMaxLotSizeQuantity", description="Maximum lot size the version is valid for."
    )
    base_unit: str | None = Field(default=None, alias="MaterialBaseUnit", description="Base unit of the material.")
    mrp_controller: str | None = Field(
        default=None,
        alias="MRPController",
        description="MRP controller - the person or group responsible for planning the material.",
    )
    lock: str | None = Field(
        default=None,
        alias="ProductionVersionLock",
        description="Lock indicator: empty = not locked, '1' = locked for any usage, '2' = locked for automatic selection.",
    )


class SAPProductionVersionQueryModel(SAPODataQueryModel):
    """Search criteria for SAP production versions (API_PRODUCTION_VERSION, OData V4)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "material": "Material {direction},Plant {direction},ProductionVersion {direction}"
    }
    sort_by: Literal["material"] = Field(default="material", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    material: Annotated[SAPCode | None, ODataCondition("Material")] = Field(
        default=None, description="Material (product) of the production versions."
    )
    plant: Annotated[SAPCode | None, ODataCondition("Plant")] = Field(
        default=None, description="Plant of the production versions, e.g. '1010'."
    )
    production_versions: Annotated[list[SAPCode] | None, ODataCondition("ProductionVersion")] = Field(
        default=None, description="Production version IDs, e.g. ['0001']."
    )
    valid_on: Annotated[date | None, ODataCondition(("ValidityStartDate", "ValidityEndDate"), operator="valid_on")] = (
        Field(
            default=None, description="Only production versions valid on this date (e.g. today for the current ones)."
        )
    )


class SAPWorkCenterResponseModel(SAPODataModel):
    """A work center as returned by SAP (API_WORK_CENTERS, OData V2).

    The key is the internal ID plus type - the work center code (e.g. "1904") is
    only unique within a plant.

    """

    internal_id: str = Field(
        alias="WorkCenterInternalID",
        description="Internal work center ID (object ID, part of the key) - not the work center code.",
    )
    type_code: str = Field(
        alias="WorkCenterTypeCode",
        description="Object type of the work center, e.g. 'A' (work center). Part of the key.",
    )
    work_center: str | None = Field(
        default=None,
        alias="WorkCenter",
        description="Work center - the people or machines (with capacity) that perform the work; see get_work_center().",
    )
    description: str | None = Field(default=None, alias="WorkCenterDesc", description="Description of the work center.")
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    category: str | None = Field(
        default=None,
        alias="WorkCenterCategoryCode",
        description="Work center category, e.g. '0005' (plant maintenance), '0001' (machine).",
    )
    responsible: str | None = Field(
        default=None, alias="WorkCenterResponsible", description="Person responsible for the work center (code)."
    )
    usage: str | None = Field(default=None, alias="WorkCenterUsage", description="Task list usage of the work center.")
    validity_start_date: ODataDate = Field(
        default=None, alias="ValidityStartDate", description="Start of the validity period."
    )
    validity_end_date: ODataDate = Field(
        default=None, alias="ValidityEndDate", description="End of the validity period."
    )
    is_to_be_deleted: bool | None = Field(
        default=None, alias="WorkCenterIsToBeDeleted", description="True if the work center is marked for deletion."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None,
        alias="WorkCenterLastChangeDateTime",
        description="Timestamp of the last change of the work center (timezone-aware).",
    )


class SAPWorkCenterQueryModel(SAPODataQueryModel):
    """Search criteria for SAP work centers (API_WORK_CENTERS)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"plant": "Plant {direction},WorkCenter {direction}"}
    sort_by: Literal["plant"] = Field(default="plant", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    work_center_ids: Annotated[list[SAPCode] | None, ODataCondition("WorkCenter")] = Field(
        default=None, description="Work center IDs, e.g. ['RES-0100']."
    )
    plant: Annotated[SAPCode | None, ODataCondition("Plant")] = Field(
        default=None, description="Plant of the work centers, e.g. '1010'."
    )
    categories: Annotated[list[SAPCode] | None, ODataCondition("WorkCenterCategoryCode")] = Field(
        default=None, description="Work center categories, e.g. ['0005'] (plant maintenance). System specific."
    )
    responsible: Annotated[SAPCode | None, ODataCondition("WorkCenterResponsible")] = Field(
        default=None, description="Person responsible for the work center."
    )
    usages: Annotated[list[SAPCode] | None, ODataCondition("WorkCenterUsage")] = Field(
        default=None, description="Task list usages of the work center. System specific."
    )
    description_contains: Annotated[str | None, ODataCondition("WorkCenterDesc", operator="contains")] = Field(
        default=None, description="Text contained in the work center description (case-sensitive)."
    )


class SAPEquipmentResponseModel(SAPODataModel):
    """An equipment (technical object) as returned by SAP (API_EQUIPMENT, OData V2).

    Equipment data is time dependent - the key includes the end of the validity period.

    """

    equipment_id: str = Field(
        alias="Equipment",
        description="Equipment - an individual technical object (e.g. a pump) that is maintained; see get_equipment().",
    )
    validity_end_date: ODataDate = Field(
        default=None,
        alias="ValidityEndDate",
        description="End of the validity of this time segment (part of the key, usually 9999-12-31).",
    )
    validity_start_date: ODataDate = Field(
        default=None, alias="ValidityStartDate", description="Start of the validity of this time segment."
    )
    name: str | None = Field(default=None, alias="EquipmentName", description="Description of the equipment.")
    category: str | None = Field(
        default=None, alias="EquipmentCategory", description="Equipment category, e.g. 'M' (machines)."
    )
    technical_object_type: str | None = Field(
        default=None, alias="TechnicalObjectType", description="Technical object type (classification), e.g. 'PUMP'."
    )
    maintenance_plant: str | None = Field(
        default=None,
        alias="MaintenancePlant",
        description="Maintenance plant - the plant in which the technical object is installed.",
    )
    planning_plant: str | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant - the plant whose planner groups plan and schedule the maintenance work.",
    )
    planner_group: str | None = Field(
        default=None,
        alias="MaintenancePlannerGroup",
        description="Planner group - the team that plans the maintenance work.",
    )
    main_work_center: str | None = Field(
        default=None,
        alias="MainWorkCenter",
        description="Main work center - responsible for executing the maintenance work; see get_work_center().",
    )
    main_work_center_plant: str | None = Field(
        default=None, alias="MainWorkCenterPlant", description="Plant of the main work center."
    )
    functional_location: str | None = Field(
        default=None,
        alias="FunctionalLocationLabelName",
        description="Functional location label as shown in the SAP UI, e.g. 'C1-B01-1'.",
    )
    superordinate_equipment: str | None = Field(
        default=None,
        alias="SuperordinateEquipment",
        description="Superordinate equipment, if installed in another equipment.",
    )
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    serial_number: str | None = Field(default=None, alias="SerialNumber", description="Serial number.")
    manufacturer: str | None = Field(
        default=None, alias="AssetManufacturerName", description="Manufacturer of the technical object."
    )
    model: str | None = Field(
        default=None, alias="ManufacturerPartTypeName", description="Model (type designation) of the manufacturer."
    )
    manufacturer_serial_number: str | None = Field(
        default=None, alias="ManufacturerSerialNumber", description="Serial number of the manufacturer."
    )
    location: str | None = Field(default=None, alias="AssetLocation", description="Location (site) of the equipment.")
    plant_section: str | None = Field(
        default=None,
        alias="PlantSection",
        description="Plant section - area of the plant, used to determine the person responsible for the location.",
    )
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    cost_center: str | None = Field(
        default=None,
        alias="CostCenter",
        description="Cost center that is charged with the costs; see get_cost_center().",
    )
    operation_start_date: ODataDate = Field(
        default=None,
        alias="OperationStartDate",
        description="Start-up date - when the equipment was put into operation.",
    )
    acquisition_date: ODataDate = Field(
        default=None, alias="AcquisitionDate", description="Date on which the equipment was acquired."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date on which the equipment master record was created."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None,
        alias="LastChangeDateTime",
        description="Timestamp of the last change of the equipment (timezone-aware).",
    )
    functional_location_id: str | None = Field(
        default=None,
        alias="FunctionalLocation",
        description="Functional location (internal ID) - a place in the technical structure where equipment is installed; see get_functional_location().",
    )


class SAPEquipmentQueryModel(SAPODataQueryModel):
    """Search criteria for SAP equipment (API_EQUIPMENT)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"equipment": "Equipment {direction},ValidityEndDate desc"}
    sort_by: Literal["equipment"] = Field(default="equipment", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    equipment_ids: Annotated[list[SAPCode] | None, ODataCondition("Equipment")] = Field(
        default=None, description="Equipment numbers, e.g. ['210100001']."
    )
    name_contains: Annotated[str | None, ODataCondition("EquipmentName", operator="contains")] = Field(
        default=None, description="Text contained in the equipment description (case-sensitive)."
    )
    categories: Annotated[list[SAPCode] | None, ODataCondition("EquipmentCategory")] = Field(
        default=None, description="Equipment categories, e.g. ['M'] (machine). System specific."
    )
    technical_object_types: Annotated[list[SAPCode] | None, ODataCondition("TechnicalObjectType")] = Field(
        default=None, description="Technical object types. System specific."
    )
    maintenance_plant: Annotated[SAPCode | None, ODataCondition("MaintenancePlant")] = Field(
        default=None, description="Plant where the equipment is installed."
    )
    planning_plant: Annotated[SAPCode | None, ODataCondition("MaintenancePlanningPlant")] = Field(
        default=None, description="Plant that plans the maintenance of the equipment."
    )
    functional_location: Annotated[str | None, ODataCondition("FunctionalLocationLabelName")] = Field(
        default=None, description="Label of the functional location the equipment is installed at (as shown in the UI)."
    )
    material: Annotated[SAPCode | None, ODataCondition("Material")] = Field(
        default=None, description="Material (product) number of the equipment."
    )
    serial_number: Annotated[str | None, ODataCondition("SerialNumber")] = Field(
        default=None, description="Serial number of the equipment."
    )
    valid_on: Annotated[date | None, ODataCondition(("ValidityStartDate", "ValidityEndDate"), operator="valid_on")] = (
        Field(default=None, description="Only equipment data valid on this date (e.g. today for the current ones).")
    )


class SAPFunctionalLocationResponseModel(SAPODataModel):
    """A functional location (technical object) as returned by SAP (API_FUNCTIONALLOCATION, OData V2).

    The key is the internal ID - the label (e.g. "C1-B01-1") is the identifier shown in the UI.

    """

    functional_location_id: str = Field(
        alias="FunctionalLocation",
        description="Functional location (internal ID) - a place in the technical structure where equipment is installed; see get_functional_location().",
    )
    label: str | None = Field(
        default=None,
        alias="FunctionalLocationLabelName",
        description="Functional location label as shown in the SAP UI, e.g. 'C1-B01-1'.",
    )
    name: str | None = Field(
        default=None, alias="FunctionalLocationName", description="Description of the functional location."
    )
    category: str | None = Field(
        default=None,
        alias="FunctionalLocationCategory",
        description="Functional location category, e.g. 'M' (technical system).",
    )
    structure: str | None = Field(
        default=None, alias="FuncLocationStructure", description="Structure indicator (edit mask of the label)."
    )
    superior_label: str | None = Field(
        default=None, alias="SuperiorFuncnlLocLabelName", description="Label of the superior functional location."
    )
    technical_object_type: str | None = Field(
        default=None, alias="TechnicalObjectType", description="Technical object type (classification)."
    )
    maintenance_plant: str | None = Field(
        default=None,
        alias="MaintenancePlant",
        description="Maintenance plant - the plant in which the technical object is installed.",
    )
    planning_plant: str | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant - the plant whose planner groups plan and schedule the maintenance work.",
    )
    planner_group: str | None = Field(
        default=None,
        alias="MaintenancePlannerGroup",
        description="Planner group - the team that plans the maintenance work.",
    )
    main_work_center: str | None = Field(
        default=None,
        alias="MainWorkCenter",
        description="Main work center - responsible for executing the maintenance work; see get_work_center().",
    )
    main_work_center_plant: str | None = Field(
        default=None, alias="MainWorkCenterPlant", description="Plant of the main work center."
    )
    location: str | None = Field(default=None, alias="AssetLocation", description="Location (site).")
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    cost_center: str | None = Field(
        default=None,
        alias="CostCenter",
        description="Cost center that is charged with the costs; see get_cost_center().",
    )
    has_equipment: SAPFlag = Field(
        default=None,
        alias="FunctionalLocationHasEquipment",
        description="True if equipment can be / is installed at the functional location.",
    )
    operation_start_date: ODataDate = Field(
        default=None,
        alias="OperationStartDate",
        description="Start-up date - when the functional location was put into operation.",
    )
    acquisition_date: ODataDate = Field(
        default=None, alias="AcquisitionDate", description="Date on which the functional location (asset) was acquired."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date on which the functional location was created."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None,
        alias="LastChangeDateTime",
        description="Timestamp of the last change of the functional location (timezone-aware).",
    )
    superior_functional_location_id: str | None = Field(
        default=None,
        alias="SuperiorFunctionalLocation",
        description="Superior functional location (internal ID) in the technical structure.",
    )


class SAPFunctionalLocationQueryModel(SAPODataQueryModel):
    """Search criteria for SAP functional locations (API_FUNCTIONALLOCATION)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "functional_location": "FunctionalLocation {direction}",
        "label": "FunctionalLocationLabelName {direction}",
    }
    sort_by: Literal["functional_location", "label"] = Field(
        default="functional_location", description="Sort criterion."
    )
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    functional_location_ids: Annotated[list[str] | None, ODataCondition("FunctionalLocation")] = Field(
        default=None, description="Internal functional location IDs."
    )
    label_contains: Annotated[str | None, ODataCondition("FunctionalLocationLabelName", operator="contains")] = Field(
        default=None, description="Text contained in the functional location label as shown in the UI (case-sensitive)."
    )
    name_contains: Annotated[str | None, ODataCondition("FunctionalLocationName", operator="contains")] = Field(
        default=None, description="Text contained in the functional location description (case-sensitive)."
    )
    categories: Annotated[list[SAPCode] | None, ODataCondition("FunctionalLocationCategory")] = Field(
        default=None, description="Functional location categories, e.g. ['M']. System specific."
    )
    superior_location: Annotated[str | None, ODataCondition("SuperiorFuncnlLocLabelName")] = Field(
        default=None, description="Label of the superior functional location (as shown in the UI)."
    )
    maintenance_plant: Annotated[SAPCode | None, ODataCondition("MaintenancePlant")] = Field(
        default=None, description="Plant where the functional location is located."
    )
    planning_plant: Annotated[SAPCode | None, ODataCondition("MaintenancePlanningPlant")] = Field(
        default=None, description="Plant that plans the maintenance of the functional location."
    )


class SAPBusinessPartnerRoleResponseModel(SAPODataModel):
    """A role of a business partner (e.g. FLVN00 supplier, FLCU00 customer) as returned by SAP (API_BUSINESS_PARTNER)."""

    business_partner_id: str = Field(alias="BusinessPartner", description="Business partner number.")
    role: str = Field(
        alias="BusinessPartnerRole", description="Business partner role, e.g. 'FLVN00' (supplier), 'FLCU00' (customer)."
    )
    valid_from: ODataDateTime = Field(default=None, alias="ValidFrom", description="Start of the validity of the role.")
    valid_to: ODataDateTime = Field(default=None, alias="ValidTo", description="End of the validity of the role.")


class SAPBusinessPartnerResponseModel(SAPODataModel):
    """A business partner (person or organization) as returned by SAP (API_BUSINESS_PARTNER, OData V2).

    Suppliers and customers are business partners - 'supplier' / 'customer' contain
    the supplier / customer numbers used in documents.

    Attributes:
        roles (list[SAPBusinessPartnerRoleResponseModel] | None):
            None if the roles have not been requested ($expand), otherwise a (possibly empty) list.

    """

    business_partner_id: str = Field(alias="BusinessPartner", description="Business partner number, e.g. '10100001'.")
    category: str | None = Field(
        default=None,
        alias="BusinessPartnerCategory",
        description="Business partner category: '1' person, '2' organization, '3' group.",
    )
    full_name: str | None = Field(
        default=None, alias="BusinessPartnerFullName", description="Full name of the business partner."
    )
    name: str | None = Field(default=None, alias="BusinessPartnerName", description="Name of the business partner.")
    grouping: str | None = Field(
        default=None, alias="BusinessPartnerGrouping", description="Business partner grouping (number range / type)."
    )
    first_name: str | None = Field(default=None, alias="FirstName", description="First name (persons).")
    last_name: str | None = Field(default=None, alias="LastName", description="Last name (persons).")
    organization_name: str | None = Field(
        default=None, alias="OrganizationBPName1", description="Organization name (organizations)."
    )
    search_term: str | None = Field(default=None, alias="SearchTerm1", description="Search term.")
    supplier: str | None = Field(
        default=None,
        alias="Supplier",
        description="Supplier (vendor) number - a business partner in the supplier role; see get_vendors().",
    )
    customer: str | None = Field(
        default=None,
        alias="Customer",
        description="Customer number - a business partner in the customer role; see get_customers().",
    )
    language: str | None = Field(default=None, alias="Language", description="Correspondence language.")
    is_blocked: bool | None = Field(
        default=None, alias="BusinessPartnerIsBlocked", description="True if the business partner is centrally blocked."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    creation_time: ODataTime = Field(
        default=None, alias="CreationTime", description="Time the record was created in SAP (see creation_date)."
    )
    last_change_date: ODataDate = Field(
        default=None, alias="LastChangeDate", description="Date of the last change of the business partner."
    )
    last_change_time: ODataTime = Field(
        default=None, alias="LastChangeTime", description="Time of the last change (see last_change_date)."
    )
    birth_date: ODataDate = Field(default=None, alias="BirthDate", description="Date of birth (persons only).")
    death_date: ODataDate = Field(
        default=None, alias="BusinessPartnerDeathDate", description="Date of death (persons only)."
    )
    foundation_date: ODataDate = Field(
        default=None,
        alias="OrganizationFoundationDate",
        description="Date on which the organization was founded (organizations only).",
    )
    liquidation_date: ODataDate = Field(
        default=None,
        alias="OrganizationLiquidationDate",
        description="Date on which the organization was liquidated (organizations only).",
    )
    roles: Annotated[
        list[SAPBusinessPartnerRoleResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_BusinessPartnerRole",
        description="Roles. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPBusinessPartnerQueryModel(SAPODataQueryModel):
    """Search criteria for SAP business partners (API_BUSINESS_PARTNER)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "business_partner": "BusinessPartner {direction}",
        "name": "BusinessPartnerFullName {direction}",
    }
    EXPAND: ClassVar[str] = "to_BusinessPartnerRole"
    sort_by: Literal["business_partner", "name"] = Field(default="business_partner", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    business_partner_ids: Annotated[list[SAPCode] | None, ODataCondition("BusinessPartner")] = Field(
        default=None, description="Business partner numbers, e.g. ['17100001']."
    )
    category: Annotated[
        Literal["person", "organization"] | None,
        ODataCondition("BusinessPartnerCategory", values={"person": "1", "organization": "2"}),
    ] = Field(default=None, description="Person or organization.")
    name_contains: Annotated[str | None, ODataCondition("BusinessPartnerFullName", operator="contains")] = Field(
        default=None, description="Text contained in the full name (case-sensitive)."
    )
    search_term: Annotated[SAPCode | None, ODataCondition("SearchTerm1")] = Field(
        default=None, description="Search term (upper case), e.g. 'INLANDKUNDE'."
    )
    is_blocked: Annotated[bool | None, ODataCondition("BusinessPartnerIsBlocked")] = Field(
        default=None, description="True = only centrally blocked business partners, False = only unblocked ones."
    )
    expand_items: bool = Field(default=False, description="Also return the roles of each business partner.")


class SAPCustomerQueryModel(SAPBusinessPartnerQueryModel):
    """Search criteria for SAP customers - business partners with the customer role (API_BUSINESS_PARTNER)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "customer": "Customer {direction}",
        "name": "BusinessPartnerFullName {direction}",
    }
    BASE_CONDITIONS: ClassVar[list[str]] = ["Customer ne ''"]
    sort_by: Literal["customer", "name"] = Field(default="customer", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    customer_ids: Annotated[list[SAPCode] | None, ODataCondition("Customer")] = Field(
        default=None, description="Customer numbers, e.g. ['17100001']."
    )


class SAPVendorQueryModel(SAPBusinessPartnerQueryModel):
    """Search criteria for SAP vendors - business partners with the vendor role (API_BUSINESS_PARTNER)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "vendor": "Supplier {direction}",
        "name": "BusinessPartnerFullName {direction}",
    }
    BASE_CONDITIONS: ClassVar[list[str]] = ["Supplier ne ''"]
    sort_by: Literal["vendor", "name"] = Field(default="vendor", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    vendor_ids: Annotated[list[SAPCode] | None, ODataCondition("Supplier")] = Field(
        default=None, description="Vendor (supplier) numbers, e.g. ['17300001']."
    )


class SAPCompanyCodeResponseModel(SAPODataModel):
    """A company code as returned by SAP (API_COMPANYCODE_SRV, OData V2)."""

    company_code: str = Field(
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    name: str | None = Field(default=None, alias="CompanyCodeName", description="Name of the company code.")
    city: str | None = Field(default=None, alias="CityName", description="City.")
    country: str | None = Field(default=None, alias="Country", description="Country key (ISO), e.g. 'DE'.")
    currency: str | None = Field(
        default=None, alias="Currency", description="Local currency of the company code (ISO code), e.g. 'EUR'."
    )
    language: str | None = Field(default=None, alias="Language", description="Language key.")
    chart_of_accounts: str | None = Field(
        default=None, alias="ChartOfAccounts", description="Chart of accounts, e.g. 'YCOA'."
    )
    fiscal_year_variant: str | None = Field(
        default=None, alias="FiscalYearVariant", description="Fiscal year variant, e.g. 'K4'."
    )
    company: str | None = Field(default=None, alias="Company", description="Company (consolidation unit).")
    controlling_area: str | None = Field(
        default=None,
        alias="ControllingArea",
        description="Controlling area - the organizational unit of cost accounting that cost and profit centers belong to.",
    )
    credit_control_area: str | None = Field(default=None, alias="CreditControlArea", description="Credit control area.")


class SAPCompanyCodeQueryModel(SAPODataQueryModel):
    """Search criteria for SAP company codes (API_COMPANYCODE_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"company_code": "CompanyCode {direction}"}
    sort_by: Literal["company_code"] = Field(default="company_code", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    company_codes: Annotated[list[SAPCode] | None, ODataCondition("CompanyCode")] = Field(
        default=None, description="Company codes, e.g. ['1010']."
    )
    name_contains: Annotated[str | None, ODataCondition("CompanyCodeName", operator="contains")] = Field(
        default=None, description="Text contained in the company code name (case-sensitive)."
    )
    countries: Annotated[list[SAPCode] | None, ODataCondition("Country")] = Field(
        default=None, description="Country keys, e.g. ['DE']."
    )
    currency: Annotated[SAPCode | None, ODataCondition("Currency")] = Field(
        default=None, description="Currency, e.g. 'EUR'."
    )


class SAPSalesOrganizationTextResponseModel(SAPODataModel):
    """The (language dependent) name of a sales organization (API_SALESORGANIZATION_SRV)."""

    sales_organization: str = Field(
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    language: str = Field(alias="Language", description="Language key of the name.")
    name: str | None = Field(default=None, alias="SalesOrganizationName", description="Name of the sales organization.")


class SAPSalesOrganizationResponseModel(SAPODataModel):
    """A sales organization as returned by SAP (API_SALESORGANIZATION_SRV, OData V2).

    Attributes:
        texts (list[SAPSalesOrganizationTextResponseModel] | None):
            The names - None if they have not been requested ($expand).

    """

    sales_organization: str = Field(
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    currency: str | None = Field(
        default=None,
        alias="SalesOrganizationCurrency",
        description="Statistics currency of the sales organization (ISO code).",
    )
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    texts: Annotated[
        list[SAPSalesOrganizationTextResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(default=None, alias="to_Text", description="Names per language. None if not requested ($expand).")


class SAPSalesOrganizationQueryModel(SAPODataQueryModel):
    """Search criteria for SAP sales organizations (API_SALESORGANIZATION_SRV). Names cannot be searched."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"sales_organization": "SalesOrganization {direction}"}
    EXPAND: ClassVar[str] = "to_Text"
    sort_by: Literal["sales_organization"] = Field(default="sales_organization", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    sales_organizations: Annotated[list[SAPCode] | None, ODataCondition("SalesOrganization")] = Field(
        default=None, description="Sales organizations, e.g. ['1010']."
    )
    company_code: Annotated[SAPCode | None, ODataCondition("CompanyCode")] = Field(
        default=None, description="Company code of the sales organizations."
    )
    expand_items: bool = Field(default=False, description="Also return the names of each sales organization.")


class SAPPurchasingOrganizationResponseModel(SAPODataModel):
    """A purchasing organization as returned by SAP (API_PURCHASINGORGANIZATION, OData V4)."""

    purchasing_organization: str = Field(
        alias="PurchasingOrganization",
        description="Purchasing organization - negotiates the conditions with suppliers; see get_purchasing_organizations().",
    )
    name: str | None = Field(
        default=None, alias="PurchasingOrganizationName", description="Name of the purchasing organization."
    )
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )


class SAPPurchasingOrganizationQueryModel(SAPODataQueryModel):
    """Search criteria for SAP purchasing organizations (API_PURCHASINGORGANIZATION, OData V4)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"purchasing_organization": "PurchasingOrganization {direction}"}
    sort_by: Literal["purchasing_organization"] = Field(
        default="purchasing_organization", description="Sort criterion."
    )
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    purchasing_organizations: Annotated[list[SAPCode] | None, ODataCondition("PurchasingOrganization")] = Field(
        default=None, description="Purchasing organizations, e.g. ['1010']."
    )
    name_contains: Annotated[str | None, ODataCondition("PurchasingOrganizationName", operator="contains")] = Field(
        default=None, description="Text contained in the name (case-sensitive)."
    )
    company_code: Annotated[SAPCode | None, ODataCondition("CompanyCode")] = Field(
        default=None, description="Company code of the purchasing organizations."
    )


class SAPCostCenterTextResponseModel(SAPODataModel):
    """The (language dependent) name of a cost center (API_COSTCENTER_SRV)."""

    language: str = Field(alias="Language", description="Language key of the name.")
    name: str | None = Field(default=None, alias="CostCenterName", description="Name of the cost center.")
    description: str | None = Field(
        default=None, alias="CostCenterDescription", description="Description of the cost center."
    )


class SAPCostCenterResponseModel(SAPODataModel):
    """A cost center as returned by SAP (API_COSTCENTER_SRV, OData V2).

    Cost center data is time dependent - the key includes the end of the validity period.

    Attributes:
        texts (list[SAPCostCenterTextResponseModel] | None):
            The names - None if they have not been requested ($expand).

    """

    controlling_area: str = Field(
        alias="ControllingArea",
        description="Controlling area - the organizational unit of cost accounting that cost and profit centers belong to.",
    )
    cost_center: str = Field(
        alias="CostCenter", description="Cost center that is charged with the costs; see get_cost_center()."
    )
    validity_end_date: ODataDate = Field(
        default=None, alias="ValidityEndDate", description="End of the validity of this time segment (part of the key)."
    )
    validity_start_date: ODataDate = Field(
        default=None, alias="ValidityStartDate", description="Start of the validity of this time segment."
    )
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    category: str | None = Field(
        default=None,
        alias="CostCenterCategory",
        description="Cost center category, e.g. 'F' (production), 'H' (service).",
    )
    responsible: str | None = Field(
        default=None, alias="CostCtrResponsiblePersonName", description="Name of the person responsible."
    )
    responsible_user: str | None = Field(
        default=None, alias="CostCtrResponsibleUser", description="SAP user ID of the person responsible."
    )
    currency: str | None = Field(
        default=None, alias="CostCenterCurrency", description="Currency of the cost center (ISO code)."
    )
    profit_center: str | None = Field(
        default=None,
        alias="ProfitCenter",
        description="Profit center the values are reported on (internal profitability); see get_profit_center().",
    )
    department: str | None = Field(default=None, alias="Department", description="Department.")
    creation_date: ODataDate = Field(
        default=None, alias="CostCenterCreationDate", description="Date on which the cost center was created."
    )
    texts: Annotated[
        list[SAPCostCenterTextResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(default=None, alias="to_Text", description="Names per language. None if not requested ($expand).")


class SAPCostCenterQueryModel(SAPODataQueryModel):
    """Search criteria for SAP cost centers (API_COSTCENTER_SRV). Cost centers have validity periods - use valid_on for the current ones. Names cannot be searched."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "cost_center": "ControllingArea {direction},CostCenter {direction},ValidityEndDate desc"
    }
    EXPAND: ClassVar[str] = "to_Text"
    sort_by: Literal["cost_center"] = Field(default="cost_center", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    controlling_area: Annotated[SAPCode | None, ODataCondition("ControllingArea")] = Field(
        default=None, description="Controlling area, e.g. 'A000'."
    )
    cost_centers: Annotated[list[SAPCode] | None, ODataCondition("CostCenter")] = Field(
        default=None, description="Cost center IDs, e.g. ['10101101']."
    )
    company_code: Annotated[SAPCode | None, ODataCondition("CompanyCode")] = Field(
        default=None, description="Company code of the cost centers."
    )
    categories: Annotated[list[SAPCode] | None, ODataCondition("CostCenterCategory")] = Field(
        default=None, description="Cost center categories. System specific."
    )
    responsible_contains: Annotated[str | None, ODataCondition("CostCtrResponsiblePersonName", operator="contains")] = (
        Field(default=None, description="Text contained in the name of the person responsible (case-sensitive).")
    )
    profit_center: Annotated[SAPCode | None, ODataCondition("ProfitCenter")] = Field(
        default=None, description="Profit center the cost centers are assigned to."
    )
    valid_on: Annotated[date | None, ODataCondition(("ValidityStartDate", "ValidityEndDate"), operator="valid_on")] = (
        Field(default=None, description="Only cost centers valid on this date (e.g. today for the current ones).")
    )
    expand_items: bool = Field(default=False, description="Also return the names of each cost center.")


class SAPProfitCenterTextResponseModel(SAPODataModel):
    """The (language dependent) name of a profit center (API_PROFITCENTER_SRV)."""

    language: str = Field(alias="Language", description="Language key of the name.")
    name: str | None = Field(default=None, alias="ProfitCenterName", description="Name of the profit center.")
    long_name: str | None = Field(
        default=None, alias="ProfitCenterLongName", description="Long name of the profit center."
    )


class SAPProfitCenterResponseModel(SAPODataModel):
    """A profit center as returned by SAP (API_PROFITCENTER_SRV, OData V2).

    Profit center data is time dependent - the key includes the end of the validity period.

    Attributes:
        texts (list[SAPProfitCenterTextResponseModel] | None):
            The names - None if they have not been requested ($expand).

    """

    controlling_area: str = Field(
        alias="ControllingArea",
        description="Controlling area - the organizational unit of cost accounting that cost and profit centers belong to.",
    )
    profit_center: str = Field(
        alias="ProfitCenter",
        description="Profit center the values are reported on (internal profitability); see get_profit_center().",
    )
    validity_end_date: ODataDate = Field(
        default=None, alias="ValidityEndDate", description="End of the validity of this time segment (part of the key)."
    )
    validity_start_date: ODataDate = Field(
        default=None, alias="ValidityStartDate", description="Start of the validity of this time segment."
    )
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    responsible: str | None = Field(
        default=None, alias="ProfitCtrResponsiblePersonName", description="Name of the person responsible."
    )
    responsible_user: str | None = Field(
        default=None, alias="ProfitCtrResponsibleUser", description="SAP user ID of the person responsible."
    )
    segment: str | None = Field(default=None, alias="Segment", description="Segment for segment reporting.")
    department: str | None = Field(default=None, alias="Department", description="Department.")
    is_blocked: SAPFlag = Field(
        default=None, alias="ProfitCenterIsBlocked", description="True if the profit center is locked for postings."
    )
    creation_date: ODataDate = Field(
        default=None, alias="ProfitCenterCreationDate", description="Date on which the profit center was created."
    )
    texts: Annotated[
        list[SAPProfitCenterTextResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(default=None, alias="to_Text", description="Names per language. None if not requested ($expand).")


class SAPProfitCenterQueryModel(SAPODataQueryModel):
    """Search criteria for SAP profit centers (API_PROFITCENTER_SRV). Profit centers have validity periods - use valid_on for the current ones. Names cannot be searched."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "profit_center": "ControllingArea {direction},ProfitCenter {direction},ValidityEndDate desc"
    }
    EXPAND: ClassVar[str] = "to_Text"
    sort_by: Literal["profit_center"] = Field(default="profit_center", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    controlling_area: Annotated[SAPCode | None, ODataCondition("ControllingArea")] = Field(
        default=None, description="Controlling area, e.g. 'A000'."
    )
    profit_centers: Annotated[list[SAPCode] | None, ODataCondition("ProfitCenter")] = Field(
        default=None, description="Profit center IDs, e.g. ['YB110']."
    )
    company_code: Annotated[SAPCode | None, ODataCondition("CompanyCode")] = Field(
        default=None, description="Company code of the profit centers."
    )
    segment: Annotated[SAPCode | None, ODataCondition("Segment")] = Field(
        default=None, description="Segment of the profit centers."
    )
    responsible_contains: Annotated[
        str | None, ODataCondition("ProfitCtrResponsiblePersonName", operator="contains")
    ] = Field(default=None, description="Text contained in the name of the person responsible (case-sensitive).")
    valid_on: Annotated[date | None, ODataCondition(("ValidityStartDate", "ValidityEndDate"), operator="valid_on")] = (
        Field(default=None, description="Only profit centers valid on this date (e.g. today for the current ones).")
    )
    expand_items: bool = Field(default=False, description="Also return the names of each profit center.")


class SAPGLAccountTextResponseModel(SAPODataModel):
    """The (language dependent) name of a G/L account (API_GLACCOUNTINCHARTOFACCOUNTS_SRV)."""

    language: str = Field(alias="Language", description="Language key of the name.")
    name: str | None = Field(default=None, alias="GLAccountName", description="Short name of the G/L account.")
    long_name: str | None = Field(default=None, alias="GLAccountLongName", description="Long name of the G/L account.")


class SAPGLAccountResponseModel(SAPODataModel):
    """A G/L account of a chart of accounts as returned by SAP (API_GLACCOUNTINCHARTOFACCOUNTS_SRV, OData V2).

    Attributes:
        texts (list[SAPGLAccountTextResponseModel] | None):
            The names - None if they have not been requested ($expand).

    """

    chart_of_accounts: str = Field(
        alias="ChartOfAccounts", description="Chart of accounts, e.g. 'YCOA'. Part of the key."
    )
    gl_account: str = Field(
        alias="GLAccount", description="G/L account the values are posted to; see get_gl_account()."
    )
    account_group: str | None = Field(default=None, alias="GLAccountGroup", description="G/L account group.")
    account_type: str | None = Field(
        default=None,
        alias="GLAccountType",
        description="G/L account type: 'X' balance sheet, 'N' non-operating, 'P' primary costs, 'S' secondary costs, 'C' cash.",
    )
    is_balance_sheet_account: bool | None = Field(
        default=None, alias="IsBalanceSheetAccount", description="True for balance sheet accounts."
    )
    is_profit_loss_account: bool | None = Field(
        default=None, alias="IsProfitLossAccount", description="True for profit and loss accounts."
    )
    is_marked_for_deletion: bool | None = Field(
        default=None, alias="AccountIsMarkedForDeletion", description="True if the account is marked for deletion."
    )
    is_blocked_for_posting: bool | None = Field(
        default=None, alias="AccountIsBlockedForPosting", description="True if the account is blocked for posting."
    )
    functional_area: str | None = Field(
        default=None, alias="FunctionalArea", description="Functional area, e.g. for cost of sales accounting."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date on which the G/L account was created."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None,
        alias="LastChangeDateTime",
        description="Timestamp of the last change of the G/L account (timezone-aware).",
    )
    texts: Annotated[
        list[SAPGLAccountTextResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(default=None, alias="to_Text", description="Names per language. None if not requested ($expand).")


class SAPGLAccountQueryModel(SAPODataQueryModel):
    """Search criteria for SAP G/L accounts of a chart of accounts (API_GLACCOUNTINCHARTOFACCOUNTS_SRV). Names cannot be searched."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"gl_account": "ChartOfAccounts {direction},GLAccount {direction}"}
    EXPAND: ClassVar[str] = "to_Text"
    sort_by: Literal["gl_account"] = Field(default="gl_account", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    chart_of_accounts: Annotated[SAPCode | None, ODataCondition("ChartOfAccounts")] = Field(
        default=None, description="Chart of accounts, e.g. 'YCOA'."
    )
    gl_accounts: Annotated[list[SAPCode] | None, ODataCondition("GLAccount")] = Field(
        default=None, description="G/L account numbers, e.g. ['0061003000']."
    )
    account_groups: Annotated[list[SAPCode] | None, ODataCondition("GLAccountGroup")] = Field(
        default=None, description="G/L account groups. System specific."
    )
    account_types: Annotated[list[SAPCode] | None, ODataCondition("GLAccountType")] = Field(
        default=None, description="G/L account types, e.g. ['X'] (balance sheet), ['P'] (primary costs or revenue)."
    )
    is_balance_sheet_account: Annotated[bool | None, ODataCondition("IsBalanceSheetAccount")] = Field(
        default=None, description="True = only balance sheet accounts, False = only profit and loss accounts."
    )
    is_blocked_for_posting: Annotated[bool | None, ODataCondition("AccountIsBlockedForPosting")] = Field(
        default=None, description="True = only accounts blocked for posting, False = only accounts open for posting."
    )
    expand_items: bool = Field(default=False, description="Also return the names of each G/L account.")
