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
from dataclasses import dataclass, replace
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
    ValidationError,
    WithJsonSchema,
    computed_field,
    field_validator,
    model_validator,
)
from pydantic.json_schema import SkipJsonSchema

# OData V2 JSON format for Edm.DateTime and Edm.DateTimeOffset values:
# "/Date(<milliseconds since 1970-01-01 UTC>[+|-<offset in minutes>])/", e.g. "/Date(1724354331000+0000)/".
# This is the general OData V2 format (not SAP specific). OData V4 uses ISO 8601 instead.
ODATA_V2_DATE_PATTERN = re.compile(r"^/Date\((-?\d+)([+-]\d+)?\)/$")

# OData V2 JSON dates before 0001-01-01 UTC can't be represented as datetime. SAP sends
# these for initial (empty) date / time values, e.g. "/Date(-62135686800000+0000)/":
ODATA_V2_MIN_MILLISECONDS = -62135596800000

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
            dates, None for initial (empty) OData V2 dates, otherwise the unchanged value.

    Raises:
        ValueError:
            If the value looks like an OData V2 date but is malformed.

    """

    # Some services (e.g. API_PRODUCTION_ORDER_2_SRV) return an ABAP timestamp
    # (YYYYMMDDhhmmss in UTC, e.g. "20160412160912") - pydantic would read it as
    # milliseconds since 1970. An initial timestamp ("00000000000000") means no value:
    if isinstance(value, str) and len(value) == 14 and value.isdigit():
        return None if int(value) == 0 else datetime.strptime(value, "%Y%m%d%H%M%S").replace(tzinfo=UTC)

    if not isinstance(value, str) or not value.startswith("/Date("):
        return value

    match = ODATA_V2_DATE_PATTERN.match(value)
    if not match:
        message = "Invalid OData V2 date value -> '{}'".format(value)
        raise ValueError(message)

    milliseconds, offset_minutes = match.groups()
    if int(milliseconds) < ODATA_V2_MIN_MILLISECONDS:
        return None
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
    # SAP uses "PT24H00M00S" for the end of the day - a time cannot hold 24:00:00:
    if (hours, minutes, seconds) == (24, 0, 0):
        return dtime(23, 59, 59)

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


def unwrap_odata_single_navigation(value: dict | None) -> dict | None:
    """Unwrap the OData V2 representation of a to-one navigation property.

    Used as a pydantic "before" validator. SAP returns {"__deferred": {"uri": ...}}
    if the navigation property was not expanded, the entity if it was expanded with
    $expand and null if there is no related entity.

    Args:
        value (dict | None):
            The raw value of the navigation property.

    Returns:
        dict | None:
            The related entity or None if there is none or it has not been expanded.

    """

    if isinstance(value, dict) and "__deferred" in value:
        return None

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

# A currency as ISO 4217 code (3 letters, e.g. "EUR") - used in create and query models. The
# response models keep plain strings, as they have to accept whatever SAP returns (e.g. "").
# The pattern is checked before the value is stripped and converted to upper case:
SAPCurrency = Annotated[str, StringConstraints(strip_whitespace=True, to_upper=True, pattern=r"^\s*[A-Za-z]{3}\s*$")]

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
# SD document categories and business object types
# ---------------------------------------------------------------------------

# Names of the SD document categories (SDDocumentCategory, VBTYP) of sales and distribution documents.
# The same codes are used by all SD documents, e.g. 'C' (order) or 'M' (invoice) - see
# SAPBillingDocumentResponseModel.category_name:
SAP_SD_DOCUMENT_CATEGORIES: dict[str, str] = {
    "A": "Inquiry",
    "B": "Quotation",
    "C": "Order",
    "D": "Item Proposal",
    "E": "Scheduling Agreement",
    "F": "Scheduling Agreement with External Service Agent",
    "G": "Contract",
    "H": "Returns",
    "I": "Order without Charge",
    "J": "Delivery",
    "K": "Credit Memo Request",
    "L": "Debit Memo Request",
    "M": "Invoice",
    "N": "Invoice Cancellation",
    "O": "Credit Memo",
    "P": "Debit Memo",
    "Q": "WMS Transfer Order",
    "R": "Goods Movement",
    "S": "Credit Memo Cancellation",
    "T": "Returns Delivery for Order",
    "U": "Pro Forma Invoice",
    "V": "Purchase Order",
    "W": "Independent Requirements Plan",
    "X": "Handling Unit",
    "0": "Master Contract",
    "3": "Invoice List",
    "4": "Credit Memo List",
    "5": "Intercompany Invoice",
    "6": "Intercompany Credit Memo",
    "7": "Delivery / Shipping Notification",
    "8": "Shipment",
}


@dataclass(frozen=True)
class SAPBusinessObjectType:
    """An SAP business object type (BOR object type, transaction SWO1) with the structure of its key.

    Use SAPBusinessObjectType.get() to look up a type by its code (see SAP_BUSINESS_OBJECT_TYPES).

    Attributes:
        label (str):
            Name of the business object, e.g. "maintenance order".
        key_lengths (tuple[int, ...]):
            Lengths of the key fields in SAP's internal format, e.g. (10, 4) for a material
            document (document number and year). Empty if the key structure is unknown.
        bo_type (str):
            The code of the type, e.g. "BUS2017" - set by get().

    """

    label: str
    key_lengths: tuple[int, ...] = ()
    bo_type: str = ""

    @classmethod
    def get(cls, bo_type: str) -> "SAPBusinessObjectType":
        """Get an SAP business object type by its code.

        Args:
            bo_type (str):
                The SAP business object type, e.g. "BUS2017" (see SAP_BUSINESS_OBJECT_TYPES).

        Returns:
            SAPBusinessObjectType:
                The type or - for types that are not in SAP_BUSINESS_OBJECT_TYPES - a generic
                "object" type with unknown key structure.

        """

        return replace(SAP_BUSINESS_OBJECT_TYPES.get(bo_type) or cls(label="object"), bo_type=bo_type)

    # end method definition

    def get_key_fields(self, bo_id: str) -> tuple[str, ...]:
        """Convert the business object ID of a reference (e.g. a business workspace) into the key fields of the SAP object.

        Business object references store the key in SAP's internal format: key fields with leading
        zeros, concatenated for composite keys (e.g. "49000001232026" for material document 4900000123
        of 2026). The OData APIs expect the key fields in the external format.

        Args:
            bo_id (str):
                The business object ID, e.g. "49000001232026".

        Returns:
            tuple[str, ...]:
                The key fields in SAP's external format (ALPHA conversion: numeric keys without leading
                zeros), e.g. ("4000340",) or ("4900000123", "2026"). IDs of types with unknown key
                structure are not split.

        Raises:
            ValueError:
                If the ID does not have the length of the composite key of the type.

        """

        bo_id = bo_id.strip()
        lengths = self.key_lengths or (len(bo_id),)
        if len(lengths) == 1:
            parts = [bo_id]
        elif len(bo_id) == sum(lengths):
            offsets = [sum(lengths[:index]) for index in range(len(lengths))]
            parts = [bo_id[offset : offset + length].strip() for offset, length in zip(offsets, lengths, strict=True)]
        else:
            message = "Unexpected ID -> '{}' of SAP business object type -> '{}'.".format(bo_id, self.bo_type)
            raise ValueError(message)

        return tuple((part.lstrip("0") or "0") if part.isdigit() else part for part in parts)

    # end method definition

    def get_business_object_id(self, key_fields: tuple[str, ...]) -> str:
        """Convert the key fields of an SAP object into the business object ID of a reference (e.g. a business workspace).

        The reverse of get_key_fields(): numeric key fields get their leading zeros, composite
        keys are concatenated, e.g. ("4900000123", "2026") -> "49000001232026" for a material document.

        Args:
            key_fields (tuple[str, ...]):
                The key fields in SAP's external format, e.g. ("413",).

        Returns:
            str:
                The business object ID in SAP's internal format, e.g. "0000000413".

        Raises:
            ValueError:
                If the key structure of the type is unknown or the key fields don't match it.

        """

        if len(key_fields) != len(self.key_lengths):
            message = "Key fields -> {} don't match SAP business object type -> '{}'.".format(key_fields, self.bo_type)
            raise ValueError(message)

        parts = []
        for field, length in zip(key_fields, self.key_lengths, strict=True):
            field = str(field).strip()
            if len(field) > length:
                message = "Key field -> '{}' is longer than {} characters.".format(field, length)
                raise ValueError(message)
            # Numeric fields with leading zeros (ALPHA conversion), others filled up with blanks:
            parts.append(field.zfill(length) if field.isdigit() else field.ljust(length))

        # References store the ID without trailing blanks (e.g. equipment 'P-3000-N001'):
        return "".join(parts).rstrip()

    # end method definition


# SAP business object types that business workspaces (and other business object references, e.g. in
# Extended ECM) can be linked to. The business object ID of a reference is the concatenation of the
# key fields in SAP's internal format, e.g. "49000001232026" for material document 4900000123 of
# 2026 (BUS2017) - see SAPBusinessObjectType.get_key_fields():
SAP_BUSINESS_OBJECT_TYPES: dict[str, SAPBusinessObjectType] = {
    "BUS2007": SAPBusinessObjectType("maintenance order", (12,)),
    "BUS2038": SAPBusinessObjectType("maintenance notification", (12,)),
    "BUS2128": SAPBusinessObjectType("maintenance order confirmation", (10, 8)),
    "BUS1020": SAPBusinessObjectType("maintenance plan", (12,)),
    "BUS1019": SAPBusinessObjectType("task list", (1, 8, 2)),
    "BUS2012": SAPBusinessObjectType("purchase order", (10,)),
    "BUS2105": SAPBusinessObjectType("purchase requisition", (10,)),
    "BUS2014": SAPBusinessObjectType("purchase contract", (10,)),
    "BUS2081": SAPBusinessObjectType("supplier invoice", (10, 4)),
    "BUS2032": SAPBusinessObjectType("sales order", (10,)),
    "BUS2034": SAPBusinessObjectType("sales contract", (10,)),
    "BUS2094": SAPBusinessObjectType("credit memo request", (10,)),
    "BUS2096": SAPBusinessObjectType("debit memo request", (10,)),
    "VBRK": SAPBusinessObjectType("billing document", (10,)),
    "BUS2037": SAPBusinessObjectType("billing document", (10,)),
    "LIKP": SAPBusinessObjectType("outbound delivery", (10,)),
    "BUS2015": SAPBusinessObjectType("inbound delivery", (10,)),
    "BUS2017": SAPBusinessObjectType("material document", (10, 4)),
    "BUS2004": SAPBusinessObjectType("planned order", (10,)),
    "BUS2005": SAPBusinessObjectType("production order", (12,)),
    "EQUI": SAPBusinessObjectType("equipment", (18,)),
    "BUS0010": SAPBusinessObjectType("functional location", (30,)),
    "BUS1001006": SAPBusinessObjectType("material", (40,)),
    "BUS1001": SAPBusinessObjectType("material", (40,)),
    "BUS1006": SAPBusinessObjectType("business partner", (10,)),
    "KNA1": SAPBusinessObjectType("customer", (10,)),
    "LFA1": SAPBusinessObjectType("vendor", (10,)),
    "BUS0002": SAPBusinessObjectType("company code", (4,)),
    "BUS0012": SAPBusinessObjectType("cost center", (4, 10)),
    "BUS0015": SAPBusinessObjectType("profit center", (4, 10)),
}


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

    # OData properties that can be set on create but not changed with an update (to_odata_update()),
    # with the reason. Some of them are silently ignored by SAP (HTTP 204 without a change):
    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {}

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
                If a field is unknown, cannot be changed (READ_ONLY_PROPERTIES), refers to
                child entities (e.g. items) or has an invalid value (pydantic.ValidationError
                is a ValueError).

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
            odata_name = field.alias or key if field else key
            if odata_name in cls.READ_ONLY_PROPERTIES:
                message = "Field -> '{}' cannot be changed - {}".format(key, cls.READ_ONLY_PROPERTIES[odata_name])
                raise ValueError(message)
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
            try:
                validated = adapter.validate_python(value)
            except ValidationError:
                # Agents often send numbers for texts (e.g. a year or a code) - accept them as text:
                if not isinstance(value, int | float | Decimal) or isinstance(value, bool):
                    raise
                validated = adapter.validate_python(format(value, "f") if isinstance(value, Decimal) else str(value))
            payload[field.alias or key] = adapter.dump_python(validated, mode="json")

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
        description=(
            "Account assignment category, e.g. 'K' (cost center), 'F' (internal order), 'P' (project), 'A' (asset), "
            "'U' (unknown - in contracts, the account assignment is given in the release orders). Required for "
            "items with account assignments (purchase orders and requisitions) and for materials without stock "
            "management (SAP: 'Account assignment mandatory for material') - system specific; copy from an "
            "existing document if unsure."
        ),
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


@dataclass(frozen=True)
class ODataTextSearch:
    """Describes how the name / description criterion of a query model is resolved via a text entity set.

    Many SAP APIs keep names and descriptions in separate text entities (e.g. A_ProductDescription)
    that the main entity set cannot be filtered by (OData V2 has no any()). The texts are searched
    first and the main query is restricted to the IDs found (see SAP._resolve_text_search()).

    Attributes:
        field (str):
            The field of the query model with the search term, e.g. "description_contains".
        entity_set (str):
            The text entity set, e.g. "A_ProductDescription".
        properties (tuple[str, ...]):
            The text properties to search, e.g. ("ProductDescription",).
        key (str):
            The key property of the object in the text entity set, e.g. "Product".
        ids_field (str):
            The field of the query model that takes the IDs found, e.g. "product_ids".
        scope (tuple[tuple[str, str], ...]):
            Fields of the query model that also restrict the texts, as (field, text property),
            e.g. (("controlling_area", "ControllingArea"),).

    """

    field: str
    entity_set: str
    properties: tuple[str, ...]
    key: str
    ids_field: str
    scope: tuple[tuple[str, str], ...] = ()


def text_search_variants(term: str) -> list[str]:
    """Get the spellings of a search term for a case-insensitive text search.

    The SAP OData V2 services search texts case-sensitively and do not support tolower(), so the
    term is searched as typed, in lower case, capitalized, in title case and in upper case.

    Args:
        term (str):
            The search term, e.g. "seal kit".

    Returns:
        list[str]:
            The distinct spellings, e.g. ["seal kit", "Seal kit", "Seal Kit", "SEAL KIT"].

    """

    term = term.strip()

    return list(dict.fromkeys([term, term.lower(), term.capitalize(), term.title(), term.upper()]))


# end function text_search_variants


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
    # How the name / description criterion is resolved via a text entity set (see ODataTextSearch):
    TEXT_SEARCH: ClassVar[ODataTextSearch | None] = None

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


class SAPODataTextResponseModel(SAPODataModel):
    """An entity of a text entity set as returned by SAP - all properties are kept (see ODataTextSearch)."""

    model_config = ConfigDict(extra="allow")


class SAPODataTextQueryModel(SAPODataQueryModel):
    """Query of a text entity set for a text search (see ODataTextSearch and SAP._resolve_text_search()).

    The conditions are given as OData filter expressions - this model is only built internally.

    """

    conditions: SkipJsonSchema[list[str]] = Field(default_factory=list)
    order_by: SkipJsonSchema[str] = ""

    def to_odata(self, odata_version: int) -> dict:  # noqa: ARG002
        """Return the OData query options of the text query.

        Args:
            odata_version (int):
                The OData version of the service (not needed - the conditions are given as expressions).

        Returns:
            dict:
                The query options ($filter, $orderby).

        """

        params = {"$filter": " and ".join("({})".format(condition) for condition in self.conditions)}
        if self.order_by:
            params["$orderby"] = self.order_by

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
        oauth_scope (str):
            OAuth 2.0 scope ID of the service, e.g. "ZAPI_MAINTENANCEORDER_0002". SAP generates
            it when OAuth is enabled for the service - it can differ between SAP systems.
            Empty if the service has no scope.
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
    oauth_scope: str = ""
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


class SAPAuthCheckState(StrEnum):
    """Possible results of an authentication / principal propagation health check."""

    OK = "ok"  # the checked step succeeded
    NOT_CONFIGURED = (
        "not_configured"  # required constructor parameters are missing (e.g. base_url, saml_idp_private_key)
    )
    NOT_ACTIVATED = "not_activated"  # the SAP endpoint is not activated/provisioned (ICF node, SOAUTH2, SAML2)
    REJECTED = "rejected"  # SAP rejected the request (wrong credentials, invalid client, invalid grant, ...)
    UNREACHABLE = "unreachable"  # network / DNS / TLS / timeout problem
    ERROR = "error"  # any other error


class SAPAuthCheckStatusModel(BaseModel):
    """Result of a single step of an authentication / principal propagation health check.

    Used by SAP.check_oauth_token_endpoint() and SAP.check_principal_propagation() - see there for the
    checks they perform.

    Attributes:
        name (str):
            Short name of the checked step, e.g. "OAuth 2.0 token endpoint".
        state (SAPAuthCheckState):
            The result of the check.
        http_status (int | None):
            The HTTP status code of the check request, if one was sent.
        message (str):
            The (error) message returned by SAP or the request library.
        hint (str):
            A hint how to fix the problem (empty if the check succeeded).
        ok (bool):
            True if the check succeeded (computed - also included in model_dump() / model_dump_json()).

    """

    name: str
    state: SAPAuthCheckState
    http_status: int | None = None
    message: str = ""
    hint: str = ""

    @computed_field
    @property
    def ok(self) -> bool:
        """Return True if the check succeeded."""

        return self.state == SAPAuthCheckState.OK

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


class SAPMaintenanceOrderComponentModel(SAPODataCreateModel):
    """A component (material, e.g. a spare part) of an operation of a maintenance order (API_MAINTENANCEORDER).

    SAP reserves the material for the operation. Components cannot be part of the deep
    create of the order - SAP.create_maintenance_order() creates them after the order.

    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Product": "the material of a component cannot be changed - delete and create the component",
    }

    material: SAPCode = Field(
        alias="Product",
        description="Material (product) number of the component, e.g. 'SEAL-KIT-50'; see get_products().",
        min_length=1,
        max_length=40,
    )
    # SAP ignores the required quantity (MaintOrdOpCompRequiredQuantity) on create - the quantity in the
    # unit of entry is taken (verified in S/4HANA):
    quantity: SAPDecimal = Field(
        alias="QuantityInUnitOfEntry",
        description="Required quantity in `unit`, e.g. 1.",
        gt=0,
    )
    unit: SAPCode = Field(
        alias="UnitOfEntry",
        description="Unit of the quantity (English unit code), e.g. 'PC'.",
        min_length=1,
        max_length=3,
    )
    plant: SAPCode | None = Field(
        default=None,
        alias="Plant",
        description="Plant the material is taken from, e.g. '3000'. Defaults to the plant of the operation.",
        max_length=4,
    )
    storage_location: SAPCode | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location the material is taken from, e.g. '0001'.",
        max_length=4,
    )
    item_category: SAPCode = Field(
        default="L",
        alias="MaintComponentItemCategory",
        description="Item category: 'L' stock item (reservation), 'N' non-stock item (purchase requisition).",
        min_length=1,
        max_length=1,
    )
    text: str | None = Field(
        default=None,
        alias="MaintOrdOperationComponentText",
        description="Item text of the component.",
        max_length=40,
    )


class SAPTaskListReferenceModel(SAPODataCreateModel):
    """A maintenance task list whose operations and materials are taken over into a new maintenance order.

    The OData API cannot include a task list in an order (its task list fields are read
    only) - SAP.create_maintenance_order() reads the task list and creates its operations
    (and their materials as components) in the order.

    """

    task_list_type: Literal["A", "E", "T"] = Field(
        alias="TaskListType",
        description="Task list type: 'A' general, 'E' equipment, 'T' functional location task list.",
    )
    task_list_group: SAPCode = Field(
        alias="TaskListGroup",
        description="Task list group, e.g. '17'; see get_task_lists().",
        min_length=1,
        max_length=8,
    )
    task_list_group_counter: SAPCode = Field(
        default="1",
        alias="TaskListGroupCounter",
        description="Task list group counter, e.g. '1'.",
        min_length=1,
        max_length=2,
    )
    storage_location: SAPCode | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location the materials of the task list are taken from, e.g. '0001'.",
        max_length=4,
    )


class SAPMaintenanceOrderOperationModel(SAPODataCreateModel):
    """An operation of an SAP Plant Maintenance order (API_MAINTENANCEORDER).

    Additional OData properties of the operation that are not modelled here can be
    passed with their OData name (e.g. "MaintOrdOperationWorkDuration"). The components
    (materials) of the operation are created after the order.

    See: https://api.sap.com/api/API_MAINTENANCEORDER/overview

    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        # Verified in S/4HANA: SAP recalculates the duration ("CN/702 Calculation executed"):
        "MaintOrderOperationDuration": "SAP calculates the duration from the work and the number of capacities - "
        "change MaintOrdOperationWorkDuration or NumberOfCapacities instead",
    }

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
        description="Operation control key. Practically mandatory - the API applies no default and rejects operations without one. E.g. 'PM01' (standard), 'YBM1' (S/4HANA Cloud) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
    planned_work: SAPDecimal | None = Field(
        default=None,
        alias="MaintOrdOperationWorkDuration",
        description="Planned work (effort) of the operation in `planned_work_unit`, e.g. 4 (hours).",
        ge=0,
    )
    planned_work_unit: SAPCode | None = Field(
        default=None,
        alias="MaintOrdOpWorkDurationUnit",
        description=(
            "Unit of the planned work (English unit code), e.g. 'HR' (hours) - use the unit of existing orders or "
            "task lists. Required with `planned_work`."
        ),
        max_length=3,
    )
    number_of_capacities: int | None = Field(
        default=None,
        alias="NumberOfCapacities",
        description="Number of people (or machines) needed for the operation, e.g. 2.",
        ge=0,
        le=255,
    )
    components: list[SAPMaintenanceOrderComponentModel] = Field(
        default_factory=list,
        alias="to_MaintOrderOpComponent_2",
        description=(
            "Components (materials, e.g. spare parts) needed by the operation - SAP reserves them. They are "
            "created after the order."
        ),
        exclude_if=is_empty,
    )


class SAPMaintenanceOrderModel(SAPODataCreateModel):
    """Data to create an SAP Plant Maintenance order (API_MAINTENANCEORDER).

    Additional OData properties of the order header that are not modelled here can
    be passed with their OData name (e.g. "ResponsibleCostCenter").

    Which fields are mandatory depends on the customizing of the order type in the
    S/4HANA system. Typically, at least an order type, a description, a planning plant,
    a main work center and a reference object (equipment or functional location) are required.

    With a task list reference (task_list), the operations and materials of the task
    list become the first operations and components of the order - the API cannot
    include a task list. Components are created after the order (SAP rejects them in
    the deep insert), see SAP.create_maintenance_order().

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
        description="Maintenance order type, e.g. 'PM01' (standard) or 'YA01' (S/4HANA Cloud) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Maintenance priority, e.g. '1' (very high) to '4' (low) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=1,
    )
    activity_type: SAPCode | None = Field(
        default=None,
        alias="MaintenanceActivityType",
        description="Maintenance activity type, e.g. '001' (inspection), '002' (repair) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=3,
    )
    planner_group: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlannerGroup",
        description="Maintenance planner group, e.g. '010' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Basic start date and time of the order, ISO 8601, e.g. '2026-11-01T08:00:00Z'; without timezone treated as UTC. Defaults to now if neither start nor end is given.",
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
    task_list: SAPTaskListReferenceModel | None = Field(
        default=None,
        alias="TaskListReference",
        description=(
            "Task list (e.g. a general task list for the construction type of the equipment) whose operations and "
            "materials become the operations and components of the order - in front of the given operations."
        ),
    )

    @model_validator(mode="after")
    def check_dates(self) -> Self:
        """Default the basic start date and validate that the basic end date is not before it."""

        # The API does not default the basic dates - without them SAP rejects the order with
        # IW/426 "Forward scheduling: Please enter start date". An end date alone is left
        # as is (backward scheduling):
        if self.basic_start_datetime is None and self.basic_end_datetime is None:
            self.basic_start_datetime = datetime.now(tz=UTC).replace(microsecond=0)

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

    def to_odata(self) -> dict:
        """Return the OData payload of the order (deep create of the order with its operations).

        The task list reference and the components of the operations are not part of it:
        SAP cannot include a task list with the API and rejects components in the deep
        create - SAP.create_maintenance_order() handles both.

        Returns:
            dict:
                The payload with OData property names.

        """

        payload = super().to_odata()
        payload.pop("TaskListReference", None)
        for operation in payload.get("to_MaintenanceOrderOperation", []):
            operation.pop("to_MaintOrderOpComponent_2", None)

        return payload

    # end method definition


class SAPMaintenanceOrderComponentResponseModel(SAPODataModel):
    """A component (material) of a maintenance order operation as returned by SAP (API_MAINTENANCEORDER)."""

    component_id: str | None = Field(
        default=None, alias="MaintOrderComponentInternalID", description="Internal ID of the component."
    )
    component: str | None = Field(
        default=None, alias="MaintenanceOrderComponent", description="Item number of the component, e.g. '0010'."
    )
    material: str | None = Field(default=None, alias="Product", description="Material (product) number.")
    text: str | None = Field(default=None, alias="MaintOrdOperationComponentText", description="Item text.")
    required_quantity: SAPDecimal | None = Field(
        default=None, alias="MaintOrdOpCompRequiredQuantity", description="Required quantity in `base_unit`."
    )
    base_unit: str | None = Field(default=None, alias="BaseUnit", description="Base unit of the material.")
    withdrawn_quantity: SAPDecimal | None = Field(
        default=None, alias="QuantityWithdrawnInBaseUnit", description="Quantity already withdrawn (goods issue)."
    )
    plant: str | None = Field(default=None, alias="Plant", description="Plant the material is taken from.")
    storage_location: str | None = Field(
        default=None, alias="StorageLocation", description="Storage location the material is taken from."
    )
    item_category: str | None = Field(
        default=None, alias="MaintComponentItemCategory", description="Item category, e.g. 'L' (stock item)."
    )
    reservation: str | None = Field(default=None, alias="Reservation", description="Reservation of the material.")
    reservation_item: str | None = Field(default=None, alias="ReservationItem", description="Item of the reservation.")


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
        default=None, alias="MaintOrdOpWorkDurationUnit", description="Unit of the planned work, e.g. 'HR' (hours)."
    )
    is_marked_for_deletion: bool | None = Field(
        default=None,
        alias="IsMarkedForDeletion",
        description="True if the operation of a released order has been deleted (deletion flag).",
    )
    components: Annotated[
        list[SAPMaintenanceOrderComponentResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_MaintOrderOpComponent_2",
        description="Components (materials) of the operation. None if not requested ($expand).",
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
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code of the order (derived by SAP from the maintenance plant); see get_company_code().",
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
        description="Code group of the damage code (catalog C, max. 8 characters) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=8,
    )
    damage_code: SAPCode | None = Field(
        default=None,
        alias="MaintNotificationDamageCode",
        description="Damage code within `damage_code_group` - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=4,
    )
    object_part_code_group: SAPCode | None = Field(
        default=None,
        alias="MaintNotifObjPrtCodeGroup",
        description="Code group of the object part code (catalog B, max. 8 characters) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=8,
    )
    object_part_code: SAPCode | None = Field(
        default=None,
        alias="MaintNotifObjPrtCode",
        description="Object part code within `object_part_code_group` - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=4,
    )


class SAPMaintenanceNotificationModel(SAPODataCreateModel):
    """Data to create an SAP maintenance notification (API_MAINTNOTIFICATION, OData V2).

    The affected object is given as technical object plus its type ("EAMS_EQUI" for
    an equipment, "EAMS_FL" for a functional location) - the API has no separate
    equipment field. The notification number is assigned by SAP. The notification date
    and the malfunction dates can be in the past (the creation date of the record is
    always today); SAP may determine the required dates from the priority.

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
        description="Notification type, e.g. 'M1' (maintenance request), 'M2' (malfunction report) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Maintenance priority, e.g. '1' (very high) to '4' (low) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Maintenance planner group, e.g. '010' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
    breakdown: SAPFlag = Field(
        default=None,
        alias="MaintenanceObjectIsDown",
        description="True if the technical object is down (breakdown), false otherwise.",
    )
    code_group: SAPCode | None = Field(
        default=None,
        alias="MaintNotificationCodeGroup",
        description="Code group of the coding (problem category, max. 8 characters) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=8,
    )
    code: SAPCode | None = Field(
        default=None,
        alias="MaintNotificationCode",
        description="Coding code within `code_group` - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
    malfunction_end_date: ODataV2Date = Field(
        default=None,
        alias="MalfunctionEndDate",
        description="End date of the malfunction (problem solved), e.g. '2026-11-02'.",
    )
    malfunction_end_time: ODataV2Time = Field(
        default=None,
        alias="MalfunctionEndTime",
        description="End time of the malfunction, Time (HH:MM:SS), e.g. '16:00:00'.",
    )
    notification_date: ODataV2Date = Field(
        default=None,
        alias="NotificationCreationDate",
        description="Date of the notification (when the problem was reported), e.g. '2026-11-01' - can be in the past. Defaults to today.",
    )
    notification_time: ODataV2Time = Field(
        default=None,
        alias="NotificationCreationTime",
        description="Time of the notification, Time (HH:MM:SS), e.g. '08:15:00'. Defaults to now.",
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
    # OData V4 requires the unit together with the quantity (/IWBEP/CM_V4S_RUN/049) - filled
    # with the order unit of the item (see SAPPurchaseOrderItemModel.check_schedule_line_units()):
    unit: SAPCode | None = Field(
        default=None,
        alias="PurchaseOrderQuantityUnit",
        description="Order unit - the same as the item's `unit`. Omit it to use the item's unit.",
        max_length=3,
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
    # OData V4 requires the unit together with the quantity (/IWBEP/CM_V4S_RUN/049) - filled
    # with the order unit of the item (see SAPPurchaseOrderItemModel.check_units()):
    unit: SAPCode | None = Field(
        default=None,
        alias="OrderQuantityUnit",
        description="Unit of `quantity` - the item's order unit. Omit it to use the item's unit.",
        max_length=3,
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
    # OData V4 requires the unit together with the quantity (/IWBEP/CM_V4S_RUN/049):
    unit: SAPCode = Field(
        alias="PurchaseOrderQuantityUnit",
        description="Order unit as English unit code, e.g. 'PC' (piece) - copy it from an existing purchase order or the material if unsure.",
        min_length=1,
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
    # OData V4 requires the unit together with NetPriceQuantity and the currency together with
    # NetPriceAmount (/IWBEP/CM_V4S_RUN/049) - filled from the item's order unit and the purchase
    # order's currency (see check_units() and SAPPurchaseOrderModel.check_item_currencies()):
    price_unit_of_measure: SAPCode | None = Field(
        default=None,
        alias="OrderPriceUnit",
        description="Unit of `price_unit` (order price unit). Omit it to use the item's order unit.",
        max_length=3,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Currency of `net_price` - the purchase order's currency. Omit it to use the purchase order's `currency`.",
    )
    item_category: SAPCode | None = Field(
        default=None,
        alias="PurchaseOrderItemCategory",
        description="Item category: empty = standard, 'K' consignment, 'L' subcontracting, 'D' service, 'S' third-party - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=1,
    )
    tax_code: SAPCode | None = Field(
        default=None,
        alias="TaxCode",
        description="Tax code (country specific), e.g. 'V1' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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

    @model_validator(mode="after")
    def check_units(self) -> Self:
        """Fill in the order unit for the price, the schedule lines and the account assignments.

        OData V4 rejects quantities without their unit. The schedule lines must use the item's unit.

        """

        if self.price_unit is not None:
            self.price_unit_of_measure = self.price_unit_of_measure or self.unit
        for account_assignment in self.account_assignments:
            if account_assignment.quantity is not None:
                account_assignment.unit = account_assignment.unit or self.unit
        for schedule_line in self.schedule_lines:
            schedule_line.unit = schedule_line.unit or self.unit
            if schedule_line.unit != self.unit:
                message = "Schedule line -> {} has unit -> '{}' but the item -> {} has unit -> '{}'".format(
                    schedule_line.schedule_line, schedule_line.unit, self.item, self.unit
                )
                raise ValueError(message)

        return self

    # end method definition


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
                    "DocumentCurrency": "USD",
                    "_PurchaseOrderItem": [
                        {
                            "Material": "R-9010",
                            "Plant": "3000",
                            "OrderQuantity": 20,
                            "PurchaseOrderQuantityUnit": "PC",
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
        description="Purchase order type. 'NB' (standard purchase order, default); the API supports NB and copies of it - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
    currency: SAPCurrency | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Defaults to the currency of the supplier.",
    )
    order_date: date | None = Field(
        default=None,
        alias="PurchaseOrderDate",
        description="Purchase order date, e.g. '2026-11-01'. Defaults to today.",
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="PaymentTerms",
        description="Terms of payment key, e.g. '0001'. Defaults to the supplier's terms - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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

    @model_validator(mode="after")
    def check_item_currencies(self) -> Self:
        """Fill in the purchase order's currency for the item prices (OData V4 needs the currency with the amount)."""

        for item in self.items:
            if item.net_price is not None:
                item.currency = item.currency or self.currency
                if not item.currency:
                    message = (
                        "Item -> {} has a `net_price` but no currency - give the purchase order's `currency`".format(
                            item.item
                        )
                    )
                    raise ValueError(message)

        return self

    # end method definition


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
        default=None, alias="PurchaseOrderQuantityUnit", description="Order unit (English unit code), e.g. 'PC'."
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
        default=None, alias="PurchaseOrderQuantityUnit", description="Order unit (English unit code), e.g. 'PC'."
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
    invoice_is_goods_receipt_based: SAPFlag = Field(
        default=None,
        alias="InvoiceIsGoodsReceiptBased",
        description=(
            "True if the item uses goods-receipt-based invoice verification: each invoice item for it refers to a "
            "goods receipt (material document) - see SAPSupplierInvoicePurchaseOrderItemModel.reference_document."
        ),
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
        description="Supplier (vendor) number - a business partner in the supplier role; see get_suppliers().",
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
        description="Sales unit (English unit code, max. 3 characters), e.g. 'PC' (piece) - internal codes like 'ST' are rejected. Defaults to the sales unit of the material.",
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
        description="Sales document item category, e.g. 'TAN' (standard item). Usually determined automatically - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Sales document type, e.g. 'OR' / 'TA' (standard order) or 'YT' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Sales group - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=3,
    )
    sales_office: SAPCode | None = Field(
        default=None,
        alias="SalesOffice",
        description="Sales office - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Terms of payment key, e.g. '0001'. Defaults to the customer's terms - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=4,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="TransactionCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Defaults to the currency of the customer.",
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
        default=None, alias="RequestedQuantityUnit", description="Sales unit (English unit code, e.g. 'PC')."
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
        description="Sales unit (English unit code, max. 3 characters), e.g. 'PC' (piece) - internal codes like 'ST' are rejected. Defaults to the sales unit of the material.",
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
        description="Sales document item category. Usually determined automatically - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Sales contract type, e.g. 'CQ' (quantity contract), 'WK1' (value contract) or 'YC' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Terms of payment key, e.g. '0001' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=4,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="TransactionCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Defaults to the currency of the customer.",
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
        default=None, alias="RequestedQuantityUnit", description="Sales unit (English unit code, e.g. 'PC')."
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
        alias="SlsContrItemReleasedQuantity",
        description="Quantity already released (called off) from the contract.",
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
    For quantity contracts ("MK") the target quantity is required. Materials without
    stock management in the plant need an account assignment category ('U' if the
    account assignment is given in the release orders).

    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        # Verified in S/4HANA: SAP answers "MMPUR_OUTL_AGREEMENT/028 No changes have been made":
        "ContractNetPriceAmount": "the price of an existing contract item is kept in its conditions and cannot "
        "be changed with this API",
    }

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
        description="Order unit (English unit code, max. 3 characters), e.g. 'PC' (piece) - internal codes like 'ST' are rejected. Defaults to the order unit of the material.",
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
        description="Item category: empty = standard, 'M' material unknown, 'W' material group - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=1,
    )
    tax_code: SAPCode | None = Field(
        default=None,
        alias="TaxCode",
        description="Tax code (country specific), e.g. 'V1' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=2,
    )
    storage_location: SAPCode | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location the goods are delivered to, e.g. '0001' (stock materials only).",
        max_length=4,
    )
    supplier_material_number: SAPCode | None = Field(
        default=None,
        alias="SupplierMaterialNumber",
        description="Material number used by the supplier, e.g. its part number.",
        max_length=35,
    )
    # Edm.Decimal in the API - sent as string like all decimals:
    planned_delivery_days: SAPDecimal | None = Field(
        default=None,
        alias="PlannedDeliveryDurationInDays",
        description="Planned delivery time in days, e.g. 21.",
        ge=0,
        le=999,
    )


class SAPPurchaseContractModel(SAPODataCreateModel):
    """Data to create an SAP purchase contract (API_PURCHASECONTRACT_PROCESS_SRV, OData V2).

    "MK" is a quantity contract (items need a target quantity), "WK" a value
    contract (the header needs a target amount). The contract number is assigned by SAP.
    The API has no contract name or header text - only the references (12 characters
    each) and the item texts.

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
        description="Purchase contract type: 'MK' quantity contract (default), 'WK' value contract - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
    currency: SAPCurrency | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Defaults to the currency of the supplier.",
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="PaymentTerms",
        description="Terms of payment key, e.g. '0001' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=4,
    )
    your_reference: str | None = Field(
        default=None,
        alias="CorrespncExternalReference",
        description="External reference, e.g. the supplier's quotation number.",
        max_length=12,
    )
    our_reference: str | None = Field(
        default=None,
        alias="CorrespncInternalReference",
        description="Our (internal) reference, e.g. 'FRAME-2026'.",
        max_length=12,
    )
    incoterms: SAPCode | None = Field(
        default=None,
        alias="IncotermsClassification",
        description="Incoterms, e.g. 'FOB', 'EXW', 'CPT'. Defaults to the Incoterms of the supplier.",
        max_length=3,
    )
    incoterms_location: str | None = Field(
        default=None,
        alias="IncotermsLocation1",
        description="Location of the Incoterms, e.g. 'Houston'.",
        max_length=70,
    )
    supplier_quotation: SAPCode | None = Field(
        default=None,
        alias="SupplierQuotation",
        description="Number of the supplier's quotation the contract is based on, e.g. 'Q-4711'.",
        max_length=10,
    )
    quotation_date: ODataV2Date = Field(
        default=None,
        alias="QuotationSubmissionDate",
        description="Date of the supplier's quotation, e.g. '2025-01-08'.",
    )
    supplier_sales_person: str | None = Field(
        default=None,
        alias="SupplierRespSalesPersonName",
        description="Responsible salesperson at the supplier, e.g. 'Jane Smith'.",
        max_length=30,
    )
    supplier_phone: str | None = Field(
        default=None,
        alias="SupplierPhoneNumber",
        description="Phone number of the supplier's salesperson, e.g. '+1 555 0100'.",
        max_length=16,
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
        default=None, alias="OrderQuantityUnit", description="Order unit (English unit code, e.g. 'PC')."
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
        alias="PurgDocReleaseOrderQuantity",
        description="Quantity already released (called off) from the contract.",
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
        description="Supplier (vendor) number - a business partner in the supplier role; see get_suppliers().",
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
    # OData V4 requires the unit together with the quantity (/IWBEP/CM_V4S_RUN/049) - filled
    # with the unit of the item (see SAPPurchaseRequisitionItemModel.check_units_and_currency()):
    unit: SAPCode | None = Field(
        default=None,
        alias="BaseUnit",
        description="Unit of `quantity` - the item's unit. Omit it to use the item's unit.",
        max_length=3,
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
    # OData V4 requires the unit together with the quantity (/IWBEP/CM_V4S_RUN/049):
    unit: SAPCode = Field(
        alias="BaseUnit",
        description="Unit as English unit code, e.g. 'PC' (piece) - copy it from the material if unsure.",
        min_length=1,
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
    currency: SAPCurrency | None = Field(
        default=None,
        alias="PurReqnItemCurrency",
        description="Currency of the price (ISO 4217 code), e.g. 'EUR'.",
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
        description="Item category: empty = standard, 'K' consignment, 'L' subcontracting, 'D' service - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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

    @model_validator(mode="after")
    def check_units_and_currency(self) -> Self:
        """Fill in the item's unit for the account assignments and check the currency of the price.

        OData V4 rejects quantities without their unit and amounts without their currency.

        """

        for account_assignment in self.account_assignments:
            if account_assignment.quantity is not None:
                account_assignment.unit = account_assignment.unit or self.unit
        if self.price is not None and not self.currency:
            message = "Item -> {} has a `price` but no `currency`".format(self.item)
            raise ValueError(message)

        return self

    # end method definition


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
                            "BaseUnit": "PC",
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
        description="Purchase requisition type, 'NB' (standard, default) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
    unit: str | None = Field(
        default=None,
        alias="BaseUnit",
        description="Unit as returned by SAP - API_PURCHASEREQUISITION_2 may return internal codes, e.g. 'ST'.",
    )
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
        description="Supplier (vendor) number - a business partner in the supplier role; see get_suppliers().",
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
    items: list[SAPPurchaseRequisitionItemResponseModel] | None = Field(
        default=None,
        alias="_PurchaseRequisitionItem",
        description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPPurchaseRequisitionQueryModel(SAPODataQueryModel):
    """Search criteria for SAP purchase requisitions (API_PURCHASEREQUISITION_2, OData V4)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "requisition_id": "PurchaseRequisition {direction}",
    }
    EXPAND: ClassVar[str] = "_PurchaseRequisitionItem($expand=_PurchaseReqnAcctAssgmt)"
    sort_by: Literal["requisition_id"] = Field(default="requisition_id", description="Sort criterion.")
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
# Credit memo requests (API_CREDIT_MEMO_REQUEST_SRV, OData V2)
# ---------------------------------------------------------------------------


class SAPCreditMemoRequestItemModel(SAPODataCreateModel):
    """An item of an SAP credit memo request (API_CREDIT_MEMO_REQUEST_SRV)."""

    item: Numc6 = Field(
        default="10",
        alias="CreditMemoRequestItem",
        description="Item number (6 digits, padded), e.g. 10 -> '000010'. Unique within the credit memo request.",
    )
    material: SAPCode = Field(
        alias="Material",
        description="Material (product) number to credit, e.g. 'TG11'.",
        min_length=1,
        max_length=40,
    )
    text: str | None = Field(
        default=None,
        alias="CreditMemoRequestItemText",
        description="Short text of the item. Defaults to the material description.",
        max_length=40,
    )
    quantity: SAPDecimal = Field(
        alias="RequestedQuantity",
        description="Quantity to credit (greater than 0), e.g. 2.",
        gt=0,
        max_digits=15,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="RequestedQuantityUnit",
        description="Sales unit (English unit code, max. 3 characters), e.g. 'PC' (piece) - internal codes like 'ST' are rejected. Defaults to the sales unit of the material.",
        max_length=3,
    )
    plant: SAPCode | None = Field(
        default=None,
        alias="Plant",
        description="Plant, e.g. '1010'. Usually determined from customer / material master data.",
        max_length=4,
    )
    item_category: SAPCode | None = Field(
        default=None,
        alias="CreditMemoRequestItemCategory",
        description="Sales document item category, e.g. 'G2N'. Usually determined automatically - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=4,
    )
    customer_material: str | None = Field(
        default=None,
        alias="MaterialByCustomer",
        description="The customer's own material number.",
        max_length=35,
    )


class SAPCreditMemoRequestModel(SAPODataCreateModel):
    """Data to create an SAP credit memo request (API_CREDIT_MEMO_REQUEST_SRV, OData V2).

    A credit memo request is the sales document from which SAP creates the credit
    memo (a billing document) for the customer. The number is assigned by SAP.
    Which further fields are required depends on the customizing of the document type.

    See: https://api.sap.com/api/API_CREDIT_MEMO_REQUEST_SRV/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "CreditMemoRequestType": "CR",
                    "SalesOrganization": "1010",
                    "DistributionChannel": "10",
                    "OrganizationDivision": "00",
                    "SoldToParty": "10100001",
                    "SDDocumentReason": "001",
                    "PurchaseOrderByCustomer": "Damaged goods",
                    "to_Item": [{"Material": "TG11", "RequestedQuantity": 2}],
                }
            ]
        }
    )

    request_type: SAPCode = Field(
        alias="CreditMemoRequestType",
        description="Sales document type, e.g. 'CR' / 'G2' (credit memo request) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        min_length=1,
        max_length=4,
    )
    sales_organization: SAPCode = Field(
        alias="SalesOrganization", description="Sales organization, e.g. '1010'.", min_length=1, max_length=4
    )
    distribution_channel: SAPCode = Field(
        alias="DistributionChannel",
        description="Distribution channel, e.g. '10' (direct sales).",
        min_length=1,
        max_length=2,
    )
    division: SAPCode = Field(
        alias="OrganizationDivision", description="Division, e.g. '00' (cross-division).", min_length=1, max_length=2
    )
    sold_to_party: SAPCode = Field(
        alias="SoldToParty",
        description="Customer number of the sold-to party, e.g. '10100001'.",
        min_length=1,
        max_length=10,
    )
    order_reason: SAPCode | None = Field(
        default=None,
        alias="SDDocumentReason",
        description="Order reason - why the customer is credited, e.g. '001'. Often required for credit memo requests - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=3,
    )
    sales_group: SAPCode | None = Field(
        default=None,
        alias="SalesGroup",
        description="Sales group - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=3,
    )
    sales_office: SAPCode | None = Field(
        default=None,
        alias="SalesOffice",
        description="Sales office - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=4,
    )
    customer_reference: str | None = Field(
        default=None,
        alias="PurchaseOrderByCustomer",
        description="The customer's reference, e.g. a complaint number.",
        max_length=35,
    )
    customer_reference_date: ODataV2Date = Field(
        default=None,
        alias="CustomerPurchaseOrderDate",
        description="Date of the customer's reference, e.g. '2026-11-01'.",
    )
    pricing_date: ODataV2Date = Field(
        default=None, alias="PricingDate", description="Date used for pricing, e.g. '2026-11-01'. Defaults to today."
    )
    billing_date: ODataV2Date = Field(
        default=None, alias="BillingDocumentDate", description="Billing date of the credit memo, e.g. '2026-11-01'."
    )
    billing_block: SAPCode | None = Field(
        default=None,
        alias="HeaderBillingBlockReason",
        description="Billing block - SAP usually sets one until the request is approved, e.g. '08' - system specific.",
        max_length=2,
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="CustomerPaymentTerms",
        description="Terms of payment key, e.g. '0001'. Defaults to the customer's terms - system specific.",
        max_length=4,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="TransactionCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Defaults to the currency of the customer.",
    )
    reference_document: SAPCode | None = Field(
        default=None,
        alias="ReferenceSDDocument",
        description="Preceding sales or billing document the credit memo request refers to, e.g. the invoice '90000123'.",
        max_length=10,
    )
    items: Annotated[list[SAPCreditMemoRequestItemModel], unique_numbers("item")] = Field(
        alias="to_Item",
        description="Items of the credit memo request (at least one). Item numbers must be unique.",
        min_length=1,
    )


class SAPCreditMemoRequestItemResponseModel(SAPODataModel):
    """An item of an SAP credit memo request as returned by SAP (API_CREDIT_MEMO_REQUEST_SRV)."""

    request_id: str = Field(
        alias="CreditMemoRequest", description="Credit memo request; see get_credit_memo_request()."
    )
    item: str = Field(alias="CreditMemoRequestItem", description="Item of the credit memo request.")
    text: str | None = Field(default=None, alias="CreditMemoRequestItemText", description="Short text of the item.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    quantity: SAPDecimal | None = Field(default=None, alias="RequestedQuantity", description="Quantity to credit.")
    unit: str | None = Field(
        default=None, alias="RequestedQuantityUnit", description="Sales unit (English unit code, e.g. 'PC')."
    )
    net_amount: SAPDecimal | None = Field(
        default=None, alias="NetAmount", description="Net value of the item in the document currency."
    )
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    item_category: str | None = Field(
        default=None, alias="CreditMemoRequestItemCategory", description="Sales document item category."
    )
    process_status: str | None = Field(
        default=None,
        alias="SDProcessStatus",
        description="Overall processing status: 'A' open, 'B' in process, 'C' completed.",
    )
    billing_status: str | None = Field(
        default=None,
        alias="OrderRelatedBillingStatus",
        description="Billing status: 'A' not billed, 'B' partially billed, 'C' fully billed.",
    )
    rejection_reason: str | None = Field(
        default=None,
        alias="SalesDocumentRjcnReason",
        description="Reason for rejection (empty if the item is not rejected).",
    )
    reference_document: str | None = Field(
        default=None, alias="ReferenceSDDocument", description="Preceding document the item refers to."
    )
    reference_document_item: str | None = Field(
        default=None, alias="ReferenceSDDocumentItem", description="Item of the preceding document."
    )
    pricing_date: ODataDate = Field(default=None, alias="PricingDate", description="Date used for pricing.")


class SAPCreditMemoRequestResponseModel(SAPODataModel):
    """An SAP credit memo request as returned by SAP (API_CREDIT_MEMO_REQUEST_SRV, OData V2).

    Attributes:
        items (list[SAPCreditMemoRequestItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    request_id: str = Field(
        alias="CreditMemoRequest", description="Credit memo request; see get_credit_memo_request()."
    )
    request_type: str | None = Field(
        default=None, alias="CreditMemoRequestType", description="Sales document type, e.g. 'CR'."
    )
    sales_organization: str | None = Field(
        default=None,
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    distribution_channel: str | None = Field(
        default=None, alias="DistributionChannel", description="Distribution channel, e.g. '10' (direct sales)."
    )
    division: str | None = Field(default=None, alias="OrganizationDivision", description="Division (product line).")
    sold_to_party: str | None = Field(
        default=None, alias="SoldToParty", description="Sold-to party - the customer; see get_customers()."
    )
    order_reason: str | None = Field(
        default=None, alias="SDDocumentReason", description="Order reason - why the customer is credited."
    )
    customer_reference: str | None = Field(
        default=None, alias="PurchaseOrderByCustomer", description="The customer's reference."
    )
    request_date: ODataDate = Field(
        default=None, alias="CreditMemoRequestDate", description="Document date of the credit memo request."
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
    total_net_amount: SAPDecimal | None = Field(
        default=None, alias="TotalNetAmount", description="Total net value in the document currency."
    )
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    billing_block: str | None = Field(
        default=None,
        alias="HeaderBillingBlockReason",
        description="Billing block - the credit memo is not created while it is set (e.g. until approval).",
    )
    approval_status: str | None = Field(
        default=None,
        alias="SalesDocApprovalStatus",
        description="Approval status, e.g. empty (no approval needed), 'A' in approval, 'B' released, 'C' rejected.",
    )
    overall_status: str | None = Field(
        default=None,
        alias="OverallSDProcessStatus",
        description="Overall processing status: 'A' open, 'B' in process, 'C' completed.",
    )
    billing_status: str | None = Field(
        default=None,
        alias="OverallOrdReltdBillgStatus",
        description="Overall billing status: 'A' not billed, 'B' partially billed, 'C' fully billed.",
    )
    reference_document: str | None = Field(
        default=None, alias="ReferenceSDDocument", description="Preceding document the request refers to."
    )
    pricing_date: ODataDate = Field(default=None, alias="PricingDate", description="Date used for pricing.")
    billing_date: ODataDate = Field(
        default=None, alias="BillingDocumentDate", description="Billing date of the credit memo."
    )
    payment_terms: str | None = Field(
        default=None, alias="CustomerPaymentTerms", description="Terms of payment, e.g. '0001' - system specific."
    )
    items: Annotated[list[SAPCreditMemoRequestItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)] = (
        Field(
            default=None,
            alias="to_Item",
            description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
        )
    )


class SAPCreditMemoRequestQueryModel(SAPODataQueryModel):
    """Search criteria for SAP credit memo requests (API_CREDIT_MEMO_REQUEST_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "request_id": "CreditMemoRequest {direction}",
        "request_date": "CreditMemoRequestDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_Item"
    sort_by: Literal["request_id", "request_date"] = Field(default="request_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    request_ids: Annotated[list[SAPCode] | None, ODataCondition("CreditMemoRequest")] = Field(
        default=None, description="Credit memo request numbers, e.g. ['60000012']."
    )
    request_types: Annotated[list[SAPCode] | None, ODataCondition("CreditMemoRequestType")] = Field(
        default=None, description="Document types, e.g. ['CR']. System specific."
    )
    sold_to_party: Annotated[SAPCode | None, ODataCondition("SoldToParty")] = Field(
        default=None, description="Customer number of the sold-to party."
    )
    sales_organization: Annotated[SAPCode | None, ODataCondition("SalesOrganization")] = Field(
        default=None, description="Sales organization, e.g. '1010'."
    )
    customer_reference: Annotated[str | None, ODataCondition("PurchaseOrderByCustomer")] = Field(
        default=None, description="The customer's reference."
    )
    order_reasons: Annotated[list[SAPCode] | None, ODataCondition("SDDocumentReason")] = Field(
        default=None, description="Order reasons. System specific."
    )
    request_date_from: Annotated[date | None, ODataCondition("CreditMemoRequestDate", operator="ge")] = Field(
        default=None, description="Only credit memo requests dated on or after this date."
    )
    request_date_to: Annotated[date | None, ODataCondition("CreditMemoRequestDate", operator="le")] = Field(
        default=None, description="Only credit memo requests dated on or before this date."
    )
    approval_statuses: Annotated[list[str] | None, ODataCondition("SalesDocApprovalStatus")] = Field(
        default=None, description="Approval statuses, e.g. ['A'] (in approval)."
    )
    process_statuses: Annotated[list[SAPCode] | None, ODataCondition("OverallSDProcessStatus")] = Field(
        default=None, description="Overall processing status: 'A' open, 'B' in process, 'C' completed."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each credit memo request.")


# ---------------------------------------------------------------------------
# Debit memo requests (API_DEBIT_MEMO_REQUEST_SRV, OData V2)
# ---------------------------------------------------------------------------


class SAPDebitMemoRequestItemModel(SAPODataCreateModel):
    """An item of an SAP debit memo request (API_DEBIT_MEMO_REQUEST_SRV)."""

    item: Numc6 = Field(
        default="10",
        alias="DebitMemoRequestItem",
        description="Item number (6 digits, padded), e.g. 10 -> '000010'. Unique within the debit memo request.",
    )
    material: SAPCode = Field(
        alias="Material",
        description="Material (product) number to charge, e.g. 'TG11'.",
        min_length=1,
        max_length=40,
    )
    text: str | None = Field(
        default=None,
        alias="DebitMemoRequestItemText",
        description="Short text of the item. Defaults to the material description.",
        max_length=40,
    )
    quantity: SAPDecimal = Field(
        alias="RequestedQuantity",
        description="Quantity to charge (greater than 0), e.g. 2.",
        gt=0,
        max_digits=15,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="RequestedQuantityUnit",
        description="Sales unit (English unit code, max. 3 characters), e.g. 'PC' (piece) - internal codes like 'ST' are rejected. Defaults to the sales unit of the material.",
        max_length=3,
    )
    plant: SAPCode | None = Field(
        default=None,
        alias="Plant",
        description="Plant, e.g. '1010'. Usually determined from customer / material master data.",
        max_length=4,
    )
    item_category: SAPCode | None = Field(
        default=None,
        alias="DebitMemoRequestItemCategory",
        description="Sales document item category, e.g. 'L2N'. Usually determined automatically - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=4,
    )
    customer_material: str | None = Field(
        default=None,
        alias="MaterialByCustomer",
        description="The customer's own material number.",
        max_length=35,
    )


class SAPDebitMemoRequestModel(SAPODataCreateModel):
    """Data to create an SAP debit memo request (API_DEBIT_MEMO_REQUEST_SRV, OData V2).

    A debit memo request is the sales document from which SAP creates the debit
    memo (a billing document) - an additional charge to the customer. The number
    is assigned by SAP.

    See: https://api.sap.com/api/API_DEBIT_MEMO_REQUEST_SRV/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "DebitMemoRequestType": "DR",
                    "SalesOrganization": "1010",
                    "DistributionChannel": "10",
                    "OrganizationDivision": "00",
                    "SoldToParty": "10100001",
                    "SDDocumentReason": "002",
                    "to_Item": [{"Material": "TG11", "RequestedQuantity": 1}],
                }
            ]
        }
    )

    request_type: SAPCode = Field(
        alias="DebitMemoRequestType",
        description="Sales document type, e.g. 'DR' / 'L2' (debit memo request) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        min_length=1,
        max_length=4,
    )
    sales_organization: SAPCode = Field(
        alias="SalesOrganization", description="Sales organization, e.g. '1010'.", min_length=1, max_length=4
    )
    distribution_channel: SAPCode = Field(
        alias="DistributionChannel",
        description="Distribution channel, e.g. '10' (direct sales).",
        min_length=1,
        max_length=2,
    )
    division: SAPCode = Field(
        alias="OrganizationDivision", description="Division, e.g. '00' (cross-division).", min_length=1, max_length=2
    )
    sold_to_party: SAPCode = Field(
        alias="SoldToParty",
        description="Customer number of the sold-to party, e.g. '10100001'.",
        min_length=1,
        max_length=10,
    )
    order_reason: SAPCode | None = Field(
        default=None,
        alias="SDDocumentReason",
        description="Order reason - why the customer is charged, e.g. '002'. Often required for debit memo requests - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=3,
    )
    sales_group: SAPCode | None = Field(
        default=None,
        alias="SalesGroup",
        description="Sales group - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=3,
    )
    sales_office: SAPCode | None = Field(
        default=None,
        alias="SalesOffice",
        description="Sales office - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=4,
    )
    customer_reference: str | None = Field(
        default=None,
        alias="PurchaseOrderByCustomer",
        description="The customer's reference.",
        max_length=35,
    )
    customer_reference_date: ODataV2Date = Field(
        default=None,
        alias="CustomerPurchaseOrderDate",
        description="Date of the customer's reference, e.g. '2026-11-01'.",
    )
    pricing_date: ODataV2Date = Field(
        default=None, alias="PricingDate", description="Date used for pricing, e.g. '2026-11-01'. Defaults to today."
    )
    billing_date: ODataV2Date = Field(
        default=None, alias="BillingDocumentDate", description="Billing date of the debit memo, e.g. '2026-11-01'."
    )
    billing_block: SAPCode | None = Field(
        default=None,
        alias="HeaderBillingBlockReason",
        description="Billing block - the debit memo is not created while it is set - system specific.",
        max_length=2,
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="CustomerPaymentTerms",
        description="Terms of payment key, e.g. '0001'. Defaults to the customer's terms - system specific.",
        max_length=4,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="TransactionCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Defaults to the currency of the customer.",
    )
    reference_document: SAPCode | None = Field(
        default=None,
        alias="ReferenceSDDocument",
        description="Preceding sales or billing document the debit memo request refers to, e.g. the invoice '90000123'.",
        max_length=10,
    )
    items: Annotated[list[SAPDebitMemoRequestItemModel], unique_numbers("item")] = Field(
        alias="to_Item",
        description="Items of the debit memo request (at least one). Item numbers must be unique.",
        min_length=1,
    )


class SAPDebitMemoRequestItemResponseModel(SAPODataModel):
    """An item of an SAP debit memo request as returned by SAP (API_DEBIT_MEMO_REQUEST_SRV)."""

    request_id: str = Field(alias="DebitMemoRequest", description="Debit memo request; see get_debit_memo_request().")
    item: str = Field(alias="DebitMemoRequestItem", description="Item of the debit memo request.")
    text: str | None = Field(default=None, alias="DebitMemoRequestItemText", description="Short text of the item.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    quantity: SAPDecimal | None = Field(default=None, alias="RequestedQuantity", description="Quantity to charge.")
    unit: str | None = Field(
        default=None, alias="RequestedQuantityUnit", description="Sales unit (English unit code, e.g. 'PC')."
    )
    net_amount: SAPDecimal | None = Field(
        default=None, alias="NetAmount", description="Net value of the item in the document currency."
    )
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    item_category: str | None = Field(
        default=None, alias="DebitMemoRequestItemCategory", description="Sales document item category."
    )
    process_status: str | None = Field(
        default=None,
        alias="SDProcessStatus",
        description="Overall processing status: 'A' open, 'B' in process, 'C' completed.",
    )
    billing_status: str | None = Field(
        default=None,
        alias="OrderRelatedBillingStatus",
        description="Billing status: 'A' not billed, 'B' partially billed, 'C' fully billed.",
    )
    rejection_reason: str | None = Field(
        default=None,
        alias="SalesDocumentRjcnReason",
        description="Reason for rejection (empty if the item is not rejected).",
    )
    reference_document: str | None = Field(
        default=None, alias="ReferenceSDDocument", description="Preceding document the item refers to."
    )
    reference_document_item: str | None = Field(
        default=None, alias="ReferenceSDDocumentItem", description="Item of the preceding document."
    )
    pricing_date: ODataDate = Field(default=None, alias="PricingDate", description="Date used for pricing.")


class SAPDebitMemoRequestResponseModel(SAPODataModel):
    """An SAP debit memo request as returned by SAP (API_DEBIT_MEMO_REQUEST_SRV, OData V2).

    Attributes:
        items (list[SAPDebitMemoRequestItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    request_id: str = Field(alias="DebitMemoRequest", description="Debit memo request; see get_debit_memo_request().")
    request_type: str | None = Field(
        default=None, alias="DebitMemoRequestType", description="Sales document type, e.g. 'DR'."
    )
    sales_organization: str | None = Field(
        default=None,
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    distribution_channel: str | None = Field(
        default=None, alias="DistributionChannel", description="Distribution channel, e.g. '10' (direct sales)."
    )
    division: str | None = Field(default=None, alias="OrganizationDivision", description="Division (product line).")
    sold_to_party: str | None = Field(
        default=None, alias="SoldToParty", description="Sold-to party - the customer; see get_customers()."
    )
    order_reason: str | None = Field(
        default=None, alias="SDDocumentReason", description="Order reason - why the customer is charged."
    )
    customer_reference: str | None = Field(
        default=None, alias="PurchaseOrderByCustomer", description="The customer's reference."
    )
    request_date: ODataDate = Field(
        default=None, alias="DebitMemoRequestDate", description="Document date of the debit memo request."
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
    total_net_amount: SAPDecimal | None = Field(
        default=None, alias="TotalNetAmount", description="Total net value in the document currency."
    )
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    billing_block: str | None = Field(
        default=None,
        alias="HeaderBillingBlockReason",
        description="Billing block - the debit memo is not created while it is set.",
    )
    overall_status: str | None = Field(
        default=None,
        alias="OverallSDProcessStatus",
        description="Overall processing status: 'A' open, 'B' in process, 'C' completed.",
    )
    billing_status: str | None = Field(
        default=None,
        alias="OverallOrdReltdBillgStatus",
        description="Overall billing status: 'A' not billed, 'B' partially billed, 'C' fully billed.",
    )
    reference_document: str | None = Field(
        default=None, alias="ReferenceSDDocument", description="Preceding document the request refers to."
    )
    pricing_date: ODataDate = Field(default=None, alias="PricingDate", description="Date used for pricing.")
    billing_date: ODataDate = Field(
        default=None, alias="BillingDocumentDate", description="Billing date of the debit memo."
    )
    payment_terms: str | None = Field(
        default=None, alias="CustomerPaymentTerms", description="Terms of payment, e.g. '0001' - system specific."
    )
    items: Annotated[list[SAPDebitMemoRequestItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)] = (
        Field(
            default=None,
            alias="to_Item",
            description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
        )
    )


class SAPDebitMemoRequestQueryModel(SAPODataQueryModel):
    """Search criteria for SAP debit memo requests (API_DEBIT_MEMO_REQUEST_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "request_id": "DebitMemoRequest {direction}",
        "request_date": "DebitMemoRequestDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_Item"
    sort_by: Literal["request_id", "request_date"] = Field(default="request_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    request_ids: Annotated[list[SAPCode] | None, ODataCondition("DebitMemoRequest")] = Field(
        default=None, description="Debit memo request numbers, e.g. ['70000012']."
    )
    request_types: Annotated[list[SAPCode] | None, ODataCondition("DebitMemoRequestType")] = Field(
        default=None, description="Document types, e.g. ['DR']. System specific."
    )
    sold_to_party: Annotated[SAPCode | None, ODataCondition("SoldToParty")] = Field(
        default=None, description="Customer number of the sold-to party."
    )
    sales_organization: Annotated[SAPCode | None, ODataCondition("SalesOrganization")] = Field(
        default=None, description="Sales organization, e.g. '1010'."
    )
    customer_reference: Annotated[str | None, ODataCondition("PurchaseOrderByCustomer")] = Field(
        default=None, description="The customer's reference."
    )
    order_reasons: Annotated[list[SAPCode] | None, ODataCondition("SDDocumentReason")] = Field(
        default=None, description="Order reasons. System specific."
    )
    request_date_from: Annotated[date | None, ODataCondition("DebitMemoRequestDate", operator="ge")] = Field(
        default=None, description="Only debit memo requests dated on or after this date."
    )
    request_date_to: Annotated[date | None, ODataCondition("DebitMemoRequestDate", operator="le")] = Field(
        default=None, description="Only debit memo requests dated on or before this date."
    )
    process_statuses: Annotated[list[SAPCode] | None, ODataCondition("OverallSDProcessStatus")] = Field(
        default=None, description="Overall processing status: 'A' open, 'B' in process, 'C' completed."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each debit memo request.")


# ---------------------------------------------------------------------------
# Billing document requests (API_BILLING_DOCUMENT_REQUEST_SRV, OData V2)
# ---------------------------------------------------------------------------


class SAPBillingDocumentRequestItemResponseModel(SAPODataModel):
    """An item of an SAP billing document request as returned by SAP (API_BILLING_DOCUMENT_REQUEST_SRV)."""

    request_id: str = Field(
        alias="BillingDocumentRequest", description="Billing document request; see get_billing_document_request()."
    )
    item: str = Field(alias="BillingDocumentRequestItem", description="Item of the billing document request.")
    text: str | None = Field(
        default=None, alias="BillingDocumentRequestItemText", description="Short text of the item."
    )
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    quantity: SAPDecimal | None = Field(default=None, alias="BillingQuantity", description="Quantity to bill.")
    unit: str | None = Field(
        default=None,
        alias="BillingQuantityUnit",
        description="Unit of the billing quantity (English unit code, e.g. 'PC').",
    )
    net_amount: SAPDecimal | None = Field(default=None, alias="NetAmount", description="Net value of the item.")
    tax_amount: SAPDecimal | None = Field(default=None, alias="TaxAmount", description="Tax amount of the item.")
    gross_amount: SAPDecimal | None = Field(default=None, alias="GrossAmount", description="Gross value of the item.")
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    services_rendered_date: ODataDate = Field(
        default=None, alias="ServicesRenderedDate", description="Date on which the services were rendered."
    )
    pricing_date: ODataDate = Field(default=None, alias="PricingDate", description="Date used for pricing.")
    reference_document: str | None = Field(
        default=None, alias="ReferenceDocument", description="Document of the external (source) system that is billed."
    )
    reference_document_item: str | None = Field(
        default=None, alias="ReferenceDocumentItem", description="Item of the reference document."
    )
    profit_center: str | None = Field(default=None, alias="ProfitCenter", description="Profit center of the item.")
    cost_center: str | None = Field(default=None, alias="CostCenter", description="Cost center of the item.")
    wbs_element: str | None = Field(
        default=None, alias="WBSElement", description="WBS element (element of a project structure) of the item."
    )


class SAPBillingDocumentRequestResponseModel(SAPODataModel):
    """An SAP billing document request as returned by SAP (API_BILLING_DOCUMENT_REQUEST_SRV, OData V2).

    Billing document requests hold billing data of external systems (external billing).
    SAP creates billing documents (invoices) from them - see get_billing_documents().

    Attributes:
        items (list[SAPBillingDocumentRequestItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    request_id: str = Field(
        alias="BillingDocumentRequest", description="Billing document request; see get_billing_document_request()."
    )
    request_type: str | None = Field(
        default=None, alias="BillingDocumentRequestType", description="Type of the billing document request."
    )
    proposed_billing_document_type: str | None = Field(
        default=None,
        alias="ProposedBillingDocumentType",
        description="Type of the billing document SAP creates from the request.",
    )
    sales_organization: str | None = Field(
        default=None,
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    distribution_channel: str | None = Field(
        default=None, alias="DistributionChannel", description="Distribution channel, e.g. '10' (direct sales)."
    )
    division: str | None = Field(default=None, alias="Division", description="Division (product line).")
    sold_to_party: str | None = Field(
        default=None, alias="SoldToParty", description="Sold-to party - the customer; see get_customers()."
    )
    payer: str | None = Field(
        default=None, alias="PayerParty", description="Payer - the customer who pays the invoice; see get_customers()."
    )
    customer_reference: str | None = Field(
        default=None, alias="PurchaseOrderByCustomer", description="The customer's purchase order number."
    )
    billing_date: ODataDate = Field(
        default=None, alias="BillingDocumentDate", description="Billing date of the billing document to create."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    total_net_amount: SAPDecimal | None = Field(default=None, alias="TotalNetAmount", description="Total net value.")
    total_tax_amount: SAPDecimal | None = Field(default=None, alias="TotalTaxAmount", description="Total tax amount.")
    total_gross_amount: SAPDecimal | None = Field(
        default=None, alias="TotalGrossAmount", description="Total gross value."
    )
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    payment_terms: str | None = Field(
        default=None, alias="CustomerPaymentTerms", description="Terms of payment, e.g. '0001' - system specific."
    )
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    reference_document: str | None = Field(
        default=None, alias="ReferenceDocument", description="Document of the external (source) system that is billed."
    )
    status: str | None = Field(
        default=None,
        alias="OverallBillingDocReqStatus",
        description="Overall status, e.g. 'A' open, 'C' billed (completely processed).",
    )
    items: Annotated[
        list[SAPBillingDocumentRequestItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)
    ] = Field(
        default=None,
        alias="to_Item",
        description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPBillingDocumentRequestQueryModel(SAPODataQueryModel):
    """Search criteria for SAP billing document requests (API_BILLING_DOCUMENT_REQUEST_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "request_id": "BillingDocumentRequest {direction}",
        "billing_date": "BillingDocumentDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_Item"
    sort_by: Literal["request_id", "billing_date"] = Field(default="request_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    request_ids: Annotated[list[SAPCode] | None, ODataCondition("BillingDocumentRequest")] = Field(
        default=None, description="Billing document request numbers."
    )
    request_types: Annotated[list[SAPCode] | None, ODataCondition("BillingDocumentRequestType")] = Field(
        default=None, description="Billing document request types. System specific."
    )
    sold_to_party: Annotated[SAPCode | None, ODataCondition("SoldToParty")] = Field(
        default=None, description="Customer number of the sold-to party."
    )
    payer: Annotated[SAPCode | None, ODataCondition("PayerParty")] = Field(
        default=None, description="Customer number of the payer."
    )
    sales_organization: Annotated[SAPCode | None, ODataCondition("SalesOrganization")] = Field(
        default=None, description="Sales organization, e.g. '1010'."
    )
    billing_date_from: Annotated[date | None, ODataCondition("BillingDocumentDate", operator="ge")] = Field(
        default=None, description="Only requests with a billing date on or after this date."
    )
    billing_date_to: Annotated[date | None, ODataCondition("BillingDocumentDate", operator="le")] = Field(
        default=None, description="Only requests with a billing date on or before this date."
    )
    statuses: Annotated[list[SAPCode] | None, ODataCondition("OverallBillingDocReqStatus")] = Field(
        default=None, description="Overall statuses, e.g. ['A'] (open)."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each billing document request.")


# ---------------------------------------------------------------------------
# Billing documents - customer invoices, credit and debit memos (API_BILLING_DOCUMENT_SRV, OData V2)
# ---------------------------------------------------------------------------


class SAPBillingDocumentItemResponseModel(SAPODataModel):
    """An item of an SAP billing document as returned by SAP (API_BILLING_DOCUMENT_SRV)."""

    billing_document_id: str = Field(
        alias="BillingDocument", description="Billing document (invoice); see get_billing_document()."
    )
    item: str = Field(alias="BillingDocumentItem", description="Item of the billing document.")
    text: str | None = Field(default=None, alias="BillingDocumentItemText", description="Short text of the item.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    quantity: SAPDecimal | None = Field(default=None, alias="BillingQuantity", description="Billed quantity.")
    unit: str | None = Field(
        default=None,
        alias="BillingQuantityUnit",
        description="Unit of the billed quantity (English unit code, e.g. 'PC').",
    )
    net_amount: SAPDecimal | None = Field(default=None, alias="NetAmount", description="Net value of the item.")
    tax_amount: SAPDecimal | None = Field(default=None, alias="TaxAmount", description="Tax amount of the item.")
    gross_amount: SAPDecimal | None = Field(default=None, alias="GrossAmount", description="Gross value of the item.")
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    item_category: str | None = Field(
        default=None, alias="SalesDocumentItemCategory", description="Item category of the billed sales document item."
    )
    sales_document: str | None = Field(
        default=None,
        alias="SalesDocument",
        description="Sales document (e.g. sales order) that is billed; see get_sales_order().",
    )
    sales_document_item: str | None = Field(
        default=None, alias="SalesDocumentItem", description="Item of the sales document that is billed."
    )
    reference_document: str | None = Field(
        default=None,
        alias="ReferenceSDDocument",
        description="Preceding document of the item, e.g. the outbound delivery; see get_outbound_delivery().",
    )
    reference_document_item: str | None = Field(
        default=None, alias="ReferenceSDDocumentItem", description="Item of the preceding document."
    )
    services_rendered_date: ODataDate = Field(
        default=None, alias="ServicesRenderedDate", description="Date on which the services were rendered."
    )
    pricing_date: ODataDate = Field(default=None, alias="PricingDate", description="Date used for pricing.")
    profit_center: str | None = Field(default=None, alias="ProfitCenter", description="Profit center of the item.")
    cost_center: str | None = Field(default=None, alias="CostCenter", description="Cost center of the item.")


class SAPBillingDocumentResponseModel(SAPODataModel):
    """An SAP billing document as returned by SAP (API_BILLING_DOCUMENT_SRV, OData V2).

    Billing documents are customer invoices, credit memos, debit memos and their
    cancellations. They are created by SAP (e.g. from deliveries, credit / debit
    memo requests or billing document requests) - the API cannot create them.

    Attributes:
        items (list[SAPBillingDocumentItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    billing_document_id: str = Field(
        alias="BillingDocument", description="Billing document (invoice); see get_billing_document()."
    )
    billing_document_type: str | None = Field(
        default=None,
        alias="BillingDocumentType",
        description="Billing document type, e.g. 'F2' (invoice), 'G2' (credit memo), 'S1' (cancellation).",
    )
    category: str | None = Field(
        default=None,
        alias="SDDocumentCategory",
        description="Document category, e.g. 'M' (invoice), 'O' (credit memo).",
    )
    billing_date: ODataDate = Field(default=None, alias="BillingDocumentDate", description="Billing (invoice) date.")
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    last_change_datetime: ODataDateTime = Field(
        default=None, alias="LastChangeDateTime", description="Timestamp of the last change in SAP (timezone-aware)."
    )
    sales_organization: str | None = Field(
        default=None,
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    distribution_channel: str | None = Field(
        default=None, alias="DistributionChannel", description="Distribution channel, e.g. '10' (direct sales)."
    )
    division: str | None = Field(default=None, alias="Division", description="Division (product line).")
    sold_to_party: str | None = Field(
        default=None, alias="SoldToParty", description="Sold-to party - the customer; see get_customers()."
    )
    payer: str | None = Field(
        default=None, alias="PayerParty", description="Payer - the customer who pays the invoice; see get_customers()."
    )
    customer_reference: str | None = Field(
        default=None, alias="PurchaseOrderByCustomer", description="The customer's purchase order number."
    )
    total_net_amount: SAPDecimal | None = Field(default=None, alias="TotalNetAmount", description="Total net value.")
    tax_amount: SAPDecimal | None = Field(default=None, alias="TaxAmount", description="Total tax amount.")
    total_gross_amount: SAPDecimal | None = Field(
        default=None, alias="TotalGrossAmount", description="Total gross value (the invoice amount)."
    )
    currency: str | None = Field(default=None, alias="TransactionCurrency", description="Document currency (ISO code).")
    payment_terms: str | None = Field(
        default=None, alias="CustomerPaymentTerms", description="Terms of payment, e.g. '0001' - system specific."
    )
    payment_reference: str | None = Field(
        default=None, alias="PaymentReference", description="Payment reference the customer quotes when paying."
    )
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    fiscal_year: str | None = Field(
        default=None, alias="FiscalYear", description="Fiscal year of the accounting document."
    )
    accounting_document: str | None = Field(
        default=None, alias="AccountingDocument", description="Accounting (journal entry) document of the invoice."
    )
    is_cancelled: bool | None = Field(
        default=None, alias="BillingDocumentIsCancelled", description="True if the billing document has been cancelled."
    )
    cancelled_billing_document: str | None = Field(
        default=None,
        alias="CancelledBillingDocument",
        description="For cancellation documents: the billing document that has been cancelled.",
    )
    overall_billing_status: str | None = Field(
        default=None, alias="OverallBillingStatus", description="Overall billing status."
    )
    accounting_posting_status: str | None = Field(
        default=None,
        alias="AccountingPostingStatus",
        description="Posting status in accounting: e.g. 'A' not posted, 'C' posted, 'B' posting blocked.",
    )
    clearing_status: str | None = Field(
        default=None,
        alias="InvoiceClearingStatus",
        description="Clearing (payment) status of the invoice in accounting, e.g. 'C' cleared (paid).",
    )
    document_reference: str | None = Field(
        default=None, alias="DocumentReferenceID", description="Reference (e.g. the external invoice number)."
    )
    items: Annotated[list[SAPBillingDocumentItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)] = (
        Field(
            default=None,
            alias="to_Item",
            description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
        )
    )

    @property
    def category_name(self) -> str | None:
        """Return the name of the document category, e.g. "Invoice" or "Credit Memo" (see SAP_SD_DOCUMENT_CATEGORIES).

        A plain property (no computed field), so it is not part of the serialized data.

        Returns:
            str | None:
                The name of the category or None if the category is not set or unknown.

        """

        return SAP_SD_DOCUMENT_CATEGORIES.get(self.category or "")

    # end method definition


class SAPBillingDocumentQueryModel(SAPODataQueryModel):
    """Search criteria for SAP billing documents (API_BILLING_DOCUMENT_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "billing_document_id": "BillingDocument {direction}",
        "billing_date": "BillingDocumentDate {direction}",
        "last_change": "LastChangeDateTime {direction}",
    }
    EXPAND: ClassVar[str] = "to_Item"
    sort_by: Literal["billing_document_id", "billing_date", "last_change"] = Field(
        default="billing_document_id", description="Sort criterion."
    )
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    billing_document_ids: Annotated[list[SAPCode] | None, ODataCondition("BillingDocument")] = Field(
        default=None, description="Billing document numbers, e.g. ['90000123']."
    )
    billing_document_types: Annotated[list[SAPCode] | None, ODataCondition("BillingDocumentType")] = Field(
        default=None, description="Billing document types, e.g. ['F2'] (invoices). System specific."
    )
    sold_to_party: Annotated[SAPCode | None, ODataCondition("SoldToParty")] = Field(
        default=None, description="Customer number of the sold-to party."
    )
    payer: Annotated[SAPCode | None, ODataCondition("PayerParty")] = Field(
        default=None, description="Customer number of the payer."
    )
    sales_organization: Annotated[SAPCode | None, ODataCondition("SalesOrganization")] = Field(
        default=None, description="Sales organization, e.g. '1010'."
    )
    company_code: Annotated[SAPCode | None, ODataCondition("CompanyCode")] = Field(
        default=None, description="Company code, e.g. '1010'."
    )
    customer_reference: Annotated[str | None, ODataCondition("PurchaseOrderByCustomer")] = Field(
        default=None, description="The customer's purchase order number."
    )
    billing_date_from: Annotated[date | None, ODataCondition("BillingDocumentDate", operator="ge")] = Field(
        default=None, description="Only billing documents dated on or after this date."
    )
    billing_date_to: Annotated[date | None, ODataCondition("BillingDocumentDate", operator="le")] = Field(
        default=None, description="Only billing documents dated on or before this date."
    )
    is_cancelled: Annotated[bool | None, ODataCondition("BillingDocumentIsCancelled")] = Field(
        default=None, description="False = only billing documents that have not been cancelled."
    )
    clearing_statuses: Annotated[list[str] | None, ODataCondition("InvoiceClearingStatus")] = Field(
        default=None, description="Clearing (payment) statuses, e.g. ['A'] (not cleared - open)."
    )
    # No ODataCondition: the sales order is a property of the items, and OData V2 cannot filter
    # A_BillingDocument by its items - SAP.iter_billing_documents() resolves it via the items:
    sales_orders: list[SAPCode] | None = Field(
        default=None, description="Only billing documents with items of these sales orders, e.g. ['413']."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each billing document.")


class SAPBillingDocumentItemQueryModel(SAPODataQueryModel):
    """Search criteria for SAP billing document items (API_BILLING_DOCUMENT_SRV, A_BillingDocumentItem).

    Used to find the billing documents of sales orders (see SAP.iter_billing_documents()).

    """

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "billing_document_id": "BillingDocument {direction},BillingDocumentItem asc",
    }
    sort_by: Literal["billing_document_id"] = Field(default="billing_document_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    sales_orders: Annotated[list[SAPCode] | None, ODataCondition("SalesDocument")] = Field(
        default=None, description="Sales orders (or other sales documents) the items were billed for, e.g. ['413']."
    )
    billing_document_ids: Annotated[list[SAPCode] | None, ODataCondition("BillingDocument")] = Field(
        default=None, description="Billing document numbers, e.g. ['90000123']."
    )


# ---------------------------------------------------------------------------
# Outbound deliveries (API_OUTBOUND_DELIVERY_SRV, version 0002, OData V2)
# ---------------------------------------------------------------------------


class SAPOutboundDeliveryItemModel(SAPODataCreateModel):
    """An item of an SAP outbound delivery - a reference to the sales order item to deliver (API_OUTBOUND_DELIVERY_SRV)."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "ReferenceSDDocument": "the sales order of a delivery item cannot be changed - delete and create the delivery",
        "ReferenceSDDocumentItem": "the sales order item of a delivery item cannot be changed - delete and create the delivery",
    }

    reference_document: SAPCode = Field(
        alias="ReferenceSDDocument",
        description="Sales order to deliver, e.g. '413'; see get_sales_order().",
        min_length=1,
        max_length=10,
    )
    reference_document_item: Numc6 = Field(
        alias="ReferenceSDDocumentItem",
        description="Item of the sales order (6 digits, padded), e.g. 10 -> '000010'.",
    )
    quantity: SAPDecimal | None = Field(
        default=None,
        alias="ActualDeliveryQuantity",
        description="Quantity to deliver (greater than 0). Defaults to the open quantity of the sales order item.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="DeliveryQuantityUnit",
        description="Sales unit (English unit code), e.g. 'PC' (piece) - internal codes like 'ST' are rejected. Defaults to the unit of the sales order item.",
        max_length=3,
    )


class SAPOutboundDeliveryModel(SAPODataCreateModel):
    """Data to create an SAP outbound delivery for sales order items (API_OUTBOUND_DELIVERY_SRV, OData V2).

    The delivery number and the item numbers are assigned by SAP; the material,
    plant and customer are copied from the sales order. Further steps (picking,
    goods issue) are done with change_outbound_delivery_status().

    See: https://api.sap.com/api/OP_API_OUTBOUND_DELIVERY_SRV_0002/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "ShippingPoint": "1010",
                    "to_DeliveryDocumentItem": [{"ReferenceSDDocument": "413", "ReferenceSDDocumentItem": "10"}],
                }
            ]
        }
    )

    shipping_point: SAPCode | None = Field(
        default=None,
        alias="ShippingPoint",
        description="Shipping point that processes the delivery, e.g. '1010'. Usually required - system specific; copy from an existing delivery if unsure.",
        max_length=4,
    )
    delivery_date: ODataV2Date = Field(
        default=None, alias="DeliveryDate", description="Delivery date (arrival at the customer), e.g. '2026-11-02'."
    )
    planned_goods_issue_date: ODataV2Date = Field(
        default=None, alias="PlannedGoodsIssueDate", description="Planned goods issue date, e.g. '2026-11-01'."
    )
    bill_of_lading: str | None = Field(
        default=None, alias="BillOfLading", description="Bill of lading number.", max_length=35
    )
    delivery_block: SAPCode | None = Field(
        default=None,
        alias="DeliveryBlockReason",
        description="Delivery block - system specific.",
        max_length=2,
    )
    items: list[SAPOutboundDeliveryItemModel] = Field(
        alias="to_DeliveryDocumentItem",
        description="The sales order items to deliver (at least one).",
        min_length=1,
    )


class SAPOutboundDeliveryItemResponseModel(SAPODataModel):
    """An item of an SAP outbound delivery as returned by SAP (API_OUTBOUND_DELIVERY_SRV)."""

    delivery_id: str = Field(alias="DeliveryDocument", description="Outbound delivery; see get_outbound_delivery().")
    item: str = Field(alias="DeliveryDocumentItem", description="Item of the delivery.")
    text: str | None = Field(default=None, alias="DeliveryDocumentItemText", description="Short text of the item.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    quantity: SAPDecimal | None = Field(
        default=None, alias="ActualDeliveryQuantity", description="Delivery quantity in the sales unit."
    )
    unit: str | None = Field(
        default=None, alias="DeliveryQuantityUnit", description="Sales unit (English unit code, e.g. 'PC')."
    )
    quantity_in_base_unit: SAPDecimal | None = Field(
        default=None, alias="ActualDeliveredQtyInBaseUnit", description="Delivery quantity in the base unit."
    )
    base_unit: str | None = Field(default=None, alias="BaseUnit", description="Base unit of the material.")
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
    batch: str | None = Field(default=None, alias="Batch", description="Batch of the material.")
    item_category: str | None = Field(
        default=None, alias="DeliveryDocumentItemCategory", description="Delivery item category, e.g. 'TAN'."
    )
    reference_document: str | None = Field(
        default=None,
        alias="ReferenceSDDocument",
        description="Sales order (or other document) that is delivered; see get_sales_order().",
    )
    reference_document_item: str | None = Field(
        default=None, alias="ReferenceSDDocumentItem", description="Item of the reference document."
    )
    picking_status: str | None = Field(
        default=None,
        alias="PickingStatus",
        description="Picking status: 'A' not picked, 'B' partially picked, 'C' fully picked.",
    )
    goods_movement_status: str | None = Field(
        default=None,
        alias="GoodsMovementStatus",
        description="Goods issue status: 'A' not posted, 'C' posted.",
    )
    billing_status: str | None = Field(
        default=None,
        alias="DeliveryRelatedBillingStatus",
        description="Billing status: 'A' not billed, 'C' billed.",
    )


class SAPOutboundDeliveryResponseModel(SAPODataModel):
    """An SAP outbound delivery as returned by SAP (API_OUTBOUND_DELIVERY_SRV, OData V2).

    Attributes:
        items (list[SAPOutboundDeliveryItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    delivery_id: str = Field(alias="DeliveryDocument", description="Outbound delivery; see get_outbound_delivery().")
    delivery_type: str | None = Field(
        default=None, alias="DeliveryDocumentType", description="Delivery type, e.g. 'LF' (outbound delivery)."
    )
    shipping_point: str | None = Field(
        default=None, alias="ShippingPoint", description="Shipping point that processes the delivery."
    )
    sales_organization: str | None = Field(
        default=None,
        alias="SalesOrganization",
        description="Sales organization responsible for selling; see get_sales_organizations().",
    )
    sold_to_party: str | None = Field(
        default=None, alias="SoldToParty", description="Sold-to party - the customer; see get_customers()."
    )
    ship_to_party: str | None = Field(
        default=None, alias="ShipToParty", description="Ship-to party - the customer who receives the goods."
    )
    delivery_date: ODataDate = Field(default=None, alias="DeliveryDate", description="Delivery date.")
    planned_goods_issue_date: ODataDate = Field(
        default=None, alias="PlannedGoodsIssueDate", description="Planned goods issue date."
    )
    actual_goods_movement_date: ODataDate = Field(
        default=None, alias="ActualGoodsMovementDate", description="Date on which the goods issue was posted."
    )
    picking_date: ODataDate = Field(default=None, alias="PickingDate", description="Picking date.")
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    last_change_date: ODataDate = Field(default=None, alias="LastChangeDate", description="Date of the last change.")
    bill_of_lading: str | None = Field(default=None, alias="BillOfLading", description="Bill of lading number.")
    gross_weight: SAPDecimal | None = Field(default=None, alias="HeaderGrossWeight", description="Gross weight.")
    net_weight: SAPDecimal | None = Field(default=None, alias="HeaderNetWeight", description="Net weight.")
    weight_unit: str | None = Field(default=None, alias="HeaderWeightUnit", description="Unit of the weights.")
    delivery_block: str | None = Field(default=None, alias="DeliveryBlockReason", description="Delivery block.")
    overall_status: str | None = Field(
        default=None,
        alias="OverallSDProcessStatus",
        description="Overall processing status: 'A' open, 'B' in process, 'C' completed.",
    )
    picking_status: str | None = Field(
        default=None,
        alias="OverallPickingStatus",
        description="Overall picking status: 'A' not picked, 'B' partially picked, 'C' fully picked.",
    )
    goods_movement_status: str | None = Field(
        default=None,
        alias="OverallGoodsMovementStatus",
        description="Overall goods issue status: 'A' not posted, 'B' partially posted, 'C' posted.",
    )
    billing_status: str | None = Field(
        default=None,
        alias="OverallDelivReltdBillgStatus",
        description="Overall billing status: 'A' not billed, 'B' partially billed, 'C' billed.",
    )
    items: Annotated[list[SAPOutboundDeliveryItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)] = (
        Field(
            default=None,
            alias="to_DeliveryDocumentItem",
            description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
        )
    )


class SAPOutboundDeliveryQueryModel(SAPODataQueryModel):
    """Search criteria for SAP outbound deliveries (API_OUTBOUND_DELIVERY_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "delivery_id": "DeliveryDocument {direction}",
        "delivery_date": "DeliveryDate {direction}",
        "planned_goods_issue": "PlannedGoodsIssueDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_DeliveryDocumentItem"
    sort_by: Literal["delivery_id", "delivery_date", "planned_goods_issue"] = Field(
        default="delivery_id", description="Sort criterion."
    )
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    delivery_ids: Annotated[list[SAPCode] | None, ODataCondition("DeliveryDocument")] = Field(
        default=None, description="Delivery numbers, e.g. ['80000123']."
    )
    delivery_types: Annotated[list[SAPCode] | None, ODataCondition("DeliveryDocumentType")] = Field(
        default=None, description="Delivery types, e.g. ['LF']. System specific."
    )
    shipping_point: Annotated[SAPCode | None, ODataCondition("ShippingPoint")] = Field(
        default=None, description="Shipping point, e.g. '1010'."
    )
    sold_to_party: Annotated[SAPCode | None, ODataCondition("SoldToParty")] = Field(
        default=None, description="Customer number of the sold-to party."
    )
    ship_to_party: Annotated[SAPCode | None, ODataCondition("ShipToParty")] = Field(
        default=None, description="Customer number of the ship-to party."
    )
    sales_organization: Annotated[SAPCode | None, ODataCondition("SalesOrganization")] = Field(
        default=None, description="Sales organization, e.g. '1010'."
    )
    delivery_date_from: Annotated[date | None, ODataCondition("DeliveryDate", operator="ge")] = Field(
        default=None, description="Only deliveries with a delivery date on or after this date."
    )
    delivery_date_to: Annotated[date | None, ODataCondition("DeliveryDate", operator="le")] = Field(
        default=None, description="Only deliveries with a delivery date on or before this date."
    )
    picking_statuses: Annotated[list[SAPCode] | None, ODataCondition("OverallPickingStatus")] = Field(
        default=None, description="Overall picking statuses: 'A' not picked, 'B' partially, 'C' fully picked."
    )
    goods_movement_statuses: Annotated[list[SAPCode] | None, ODataCondition("OverallGoodsMovementStatus")] = Field(
        default=None, description="Overall goods issue statuses: 'A' not posted, 'B' partially, 'C' posted."
    )
    sales_orders: list[SAPCode] | None = Field(
        default=None, description="Only deliveries with items of these sales orders, e.g. ['172']."
    )
    materials: list[SAPCode] | None = Field(
        default=None, description="Only deliveries with items of these materials (products), e.g. ['P-100']."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each delivery.")

    @property
    def has_item_criteria(self) -> bool:
        """Whether the query has criteria of the delivery items (resolved via the items first)."""

        return bool(self.sales_orders or self.materials)


class SAPOutboundDeliveryItemQueryModel(SAPODataQueryModel):
    """Search criteria for SAP outbound delivery items (API_OUTBOUND_DELIVERY_SRV, A_OutbDeliveryItem).

    Used to find the deliveries of sales orders and materials (see SAP.iter_outbound_deliveries()).

    """

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "delivery_id": "DeliveryDocument {direction},DeliveryDocumentItem asc",
    }
    sort_by: Literal["delivery_id"] = Field(default="delivery_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    sales_orders: Annotated[list[SAPCode] | None, ODataCondition("ReferenceSDDocument")] = Field(
        default=None, description="Sales orders the items deliver, e.g. ['172']."
    )
    materials: Annotated[list[SAPCode] | None, ODataCondition("Material")] = Field(
        default=None, description="Materials (products) of the items, e.g. ['P-100']."
    )
    delivery_ids: Annotated[list[SAPCode] | None, ODataCondition("DeliveryDocument")] = Field(
        default=None, description="Delivery numbers, e.g. ['80000123']."
    )


# ---------------------------------------------------------------------------
# Inbound deliveries (API_INBOUND_DELIVERY_SRV, version 0002, OData V2)
# ---------------------------------------------------------------------------


class SAPInboundDeliveryItemModel(SAPODataCreateModel):
    """An item of an SAP inbound delivery - the delivered quantity of a purchase order item (API_INBOUND_DELIVERY_SRV)."""

    reference_document: SAPCode = Field(
        alias="ReferenceSDDocument",
        description="Purchase order that is delivered, e.g. '4500001540'; see get_purchase_order().",
        min_length=1,
        max_length=10,
    )
    reference_document_item: Numc6 = Field(
        alias="ReferenceSDDocumentItem",
        description="Item of the purchase order (6 digits, padded), e.g. 10 -> '000010'.",
    )
    quantity: SAPDecimal = Field(
        alias="ActualDeliveryQuantity",
        description="Delivered quantity (greater than 0), e.g. 5.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="DeliveryQuantityUnit",
        description="Unit (English unit code), e.g. 'PC' (piece) - internal codes like 'ST' are rejected. Defaults to the order unit of the purchase order item.",
        max_length=3,
    )
    material: SAPCode | None = Field(
        default=None,
        alias="Material",
        description="Material (product) number. Defaults to the material of the purchase order item.",
        max_length=40,
    )
    plant: SAPCode | None = Field(
        default=None,
        alias="Plant",
        description="Receiving plant, e.g. '1010'. Defaults to the plant of the purchase order item.",
        max_length=4,
    )
    storage_location: SAPCode | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location to receive the goods in, e.g. '101A'.",
        max_length=4,
    )
    batch: SAPCode | None = Field(
        default=None, alias="Batch", description="Batch (for batch managed materials).", max_length=10
    )


class SAPInboundDeliveryModel(SAPODataCreateModel):
    """Data to create an SAP inbound delivery for purchase order items (API_INBOUND_DELIVERY_SRV, OData V2).

    An inbound delivery announces the goods a supplier sends for purchase orders.
    The delivery number is assigned by SAP. Putaway and goods receipt are posted
    with change_inbound_delivery_status().

    See: https://api.sap.com/api/OP_API_INBOUND_DELIVERY_SRV_0002/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "Supplier": "10300001",
                    "DeliveryDate": "2026-11-02",
                    "DeliveryDocumentBySupplier": "DN-4711",
                    "to_DeliveryDocumentItem": [
                        {
                            "ReferenceSDDocument": "4500001540",
                            "ReferenceSDDocumentItem": "10",
                            "ActualDeliveryQuantity": 5,
                            "DeliveryQuantityUnit": "ST",
                        }
                    ],
                }
            ]
        }
    )

    supplier: SAPCode | None = Field(
        default=None,
        alias="Supplier",
        description="Supplier number, e.g. '10300001'. Defaults to the supplier of the purchase order.",
        max_length=10,
    )
    delivery_date: ODataV2Date = Field(
        default=None, alias="DeliveryDate", description="Expected delivery date, e.g. '2026-11-02'."
    )
    supplier_delivery_note: str | None = Field(
        default=None,
        alias="DeliveryDocumentBySupplier",
        description="The supplier's delivery note number, e.g. 'DN-4711'.",
        max_length=35,
    )
    bill_of_lading: str | None = Field(
        default=None, alias="BillOfLading", description="Bill of lading number.", max_length=35
    )
    items: list[SAPInboundDeliveryItemModel] = Field(
        alias="to_DeliveryDocumentItem",
        description="The purchase order items that are delivered (at least one).",
        min_length=1,
    )


class SAPInboundDeliveryItemResponseModel(SAPODataModel):
    """An item of an SAP inbound delivery as returned by SAP (API_INBOUND_DELIVERY_SRV)."""

    delivery_id: str = Field(alias="DeliveryDocument", description="Inbound delivery; see get_inbound_delivery().")
    item: str = Field(alias="DeliveryDocumentItem", description="Item of the delivery.")
    text: str | None = Field(default=None, alias="DeliveryDocumentItemText", description="Short text of the item.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    quantity: SAPDecimal | None = Field(
        default=None, alias="ActualDeliveryQuantity", description="Delivered quantity in the delivery unit."
    )
    unit: str | None = Field(
        default=None, alias="DeliveryQuantityUnit", description="Delivery unit (English unit code, e.g. 'PC')."
    )
    quantity_in_base_unit: SAPDecimal | None = Field(
        default=None, alias="ActualDeliveredQtyInBaseUnit", description="Delivered quantity in the base unit."
    )
    base_unit: str | None = Field(default=None, alias="BaseUnit", description="Base unit of the material.")
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
    batch: str | None = Field(default=None, alias="Batch", description="Batch of the material.")
    reference_document: str | None = Field(
        default=None,
        alias="ReferenceSDDocument",
        description="Purchase order that is delivered; see get_purchase_order().",
    )
    reference_document_item: str | None = Field(
        default=None, alias="ReferenceSDDocumentItem", description="Item of the purchase order."
    )
    putaway_status: str | None = Field(
        default=None,
        alias="PickingStatus",
        description="Putaway status: 'A' not put away, 'B' partially, 'C' fully put away.",
    )
    goods_movement_status: str | None = Field(
        default=None,
        alias="GoodsMovementStatus",
        description="Goods receipt status: 'A' not posted, 'C' posted.",
    )


class SAPInboundDeliveryResponseModel(SAPODataModel):
    """An SAP inbound delivery as returned by SAP (API_INBOUND_DELIVERY_SRV, OData V2).

    Attributes:
        items (list[SAPInboundDeliveryItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    delivery_id: str = Field(alias="DeliveryDocument", description="Inbound delivery; see get_inbound_delivery().")
    delivery_type: str | None = Field(
        default=None, alias="DeliveryDocumentType", description="Delivery type, e.g. 'EL' (inbound delivery)."
    )
    supplier: str | None = Field(
        default=None,
        alias="Supplier",
        description="Supplier (vendor) number - a business partner in the supplier role; see get_suppliers().",
    )
    supplier_delivery_note: str | None = Field(
        default=None, alias="DeliveryDocumentBySupplier", description="The supplier's delivery note number."
    )
    receiving_plant: str | None = Field(default=None, alias="ReceivingPlant", description="Receiving plant.")
    delivery_date: ODataDate = Field(default=None, alias="DeliveryDate", description="Expected delivery date.")
    actual_goods_movement_date: ODataDate = Field(
        default=None, alias="ActualGoodsMovementDate", description="Date on which the goods receipt was posted."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    last_change_date: ODataDate = Field(default=None, alias="LastChangeDate", description="Date of the last change.")
    bill_of_lading: str | None = Field(default=None, alias="BillOfLading", description="Bill of lading number.")
    gross_weight: SAPDecimal | None = Field(default=None, alias="HeaderGrossWeight", description="Gross weight.")
    weight_unit: str | None = Field(default=None, alias="HeaderWeightUnit", description="Unit of the weight.")
    overall_status: str | None = Field(
        default=None,
        alias="OverallSDProcessStatus",
        description="Overall processing status: 'A' open, 'B' in process, 'C' completed.",
    )
    putaway_status: str | None = Field(
        default=None,
        alias="OverallPickingStatus",
        description="Overall putaway status: 'A' not put away, 'B' partially, 'C' fully put away.",
    )
    goods_movement_status: str | None = Field(
        default=None,
        alias="OverallGoodsMovementStatus",
        description="Overall goods receipt status: 'A' not posted, 'B' partially posted, 'C' posted.",
    )
    items: Annotated[list[SAPInboundDeliveryItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)] = (
        Field(
            default=None,
            alias="to_DeliveryDocumentItem",
            description="Items. None if not requested ($expand), otherwise a (possibly empty) list.",
        )
    )


class SAPInboundDeliveryQueryModel(SAPODataQueryModel):
    """Search criteria for SAP inbound deliveries (API_INBOUND_DELIVERY_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "delivery_id": "DeliveryDocument {direction}",
        "delivery_date": "DeliveryDate {direction}",
    }
    EXPAND: ClassVar[str] = "to_DeliveryDocumentItem"
    sort_by: Literal["delivery_id", "delivery_date"] = Field(default="delivery_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    delivery_ids: Annotated[list[SAPCode] | None, ODataCondition("DeliveryDocument")] = Field(
        default=None, description="Delivery numbers, e.g. ['180000123']."
    )
    delivery_types: Annotated[list[SAPCode] | None, ODataCondition("DeliveryDocumentType")] = Field(
        default=None, description="Delivery types, e.g. ['EL']. System specific."
    )
    supplier: Annotated[SAPCode | None, ODataCondition("Supplier")] = Field(
        default=None, description="Supplier number."
    )
    supplier_delivery_note: Annotated[str | None, ODataCondition("DeliveryDocumentBySupplier")] = Field(
        default=None, description="The supplier's delivery note number."
    )
    receiving_plant: Annotated[SAPCode | None, ODataCondition("ReceivingPlant")] = Field(
        default=None, description="Receiving plant, e.g. '1010'."
    )
    delivery_date_from: Annotated[date | None, ODataCondition("DeliveryDate", operator="ge")] = Field(
        default=None, description="Only deliveries with a delivery date on or after this date."
    )
    delivery_date_to: Annotated[date | None, ODataCondition("DeliveryDate", operator="le")] = Field(
        default=None, description="Only deliveries with a delivery date on or before this date."
    )
    goods_movement_statuses: Annotated[list[SAPCode] | None, ODataCondition("OverallGoodsMovementStatus")] = Field(
        default=None, description="Overall goods receipt statuses: 'A' not posted, 'B' partially, 'C' posted."
    )
    purchase_orders: list[SAPCode] | None = Field(
        default=None, description="Only deliveries with items of these purchase orders, e.g. ['4500001540']."
    )
    materials: list[SAPCode] | None = Field(
        default=None, description="Only deliveries with items of these materials (products), e.g. ['R-9010']."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each delivery.")

    @property
    def has_item_criteria(self) -> bool:
        """Whether the query has criteria of the delivery items (resolved via the items first)."""

        return bool(self.purchase_orders or self.materials)


class SAPInboundDeliveryItemQueryModel(SAPODataQueryModel):
    """Search criteria for SAP inbound delivery items (API_INBOUND_DELIVERY_SRV, A_InbDeliveryItem).

    Used to find the inbound deliveries of purchase orders and materials (see SAP.iter_inbound_deliveries()).

    """

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "delivery_id": "DeliveryDocument {direction},DeliveryDocumentItem asc",
    }
    sort_by: Literal["delivery_id"] = Field(default="delivery_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    purchase_orders: Annotated[list[SAPCode] | None, ODataCondition("ReferenceSDDocument")] = Field(
        default=None, description="Purchase orders the items refer to, e.g. ['4500001540']."
    )
    materials: Annotated[list[SAPCode] | None, ODataCondition("Material")] = Field(
        default=None, description="Materials (products) of the items, e.g. ['R-9010']."
    )
    delivery_ids: Annotated[list[SAPCode] | None, ODataCondition("DeliveryDocument")] = Field(
        default=None, description="Delivery numbers, e.g. ['180000123']."
    )


# ---------------------------------------------------------------------------
# Supplier invoices - incoming invoices (API_SUPPLIERINVOICE_PROCESS_SRV, OData V2)
# ---------------------------------------------------------------------------


class SAPSupplierInvoiceAccountAssignmentModel(SAPODataCreateModel):
    """An account assignment of a purchase order item of a new SAP supplier invoice (API_SUPPLIERINVOICE_PROCESS_SRV).

    Needed for purchase order items with account assignment (e.g. cost center 'K'),
    e.g. to distribute the invoiced amount differently than in the purchase order.

    """

    # Filled with the item number of the purchase order item (see SAPSupplierInvoicePurchaseOrderItemModel):
    item: SkipJsonSchema[str | None] = Field(default=None, alias="SupplierInvoiceItem")
    ordinal_number: Numc4 = Field(
        default="1",
        alias="OrdinalNumber",
        description="Sequential number of the account assignment (4 digits, padded), e.g. 1 -> '0001'.",
    )
    account_assignment_number: Numc2 | None = Field(
        default=None,
        alias="AccountAssignmentNumber",
        description="Account assignment of the purchase order item it refers to (2 digits, padded), e.g. 1 -> '01'.",
    )
    amount: SAPDecimal | None = Field(
        default=None,
        alias="SuplrInvcAcctAssignmentAmount",
        description="Amount of the account assignment in the document currency, e.g. 125.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Same as the invoice.",
    )
    quantity: SAPDecimal | None = Field(
        default=None,
        alias="Quantity",
        description="Quantity of the account assignment in the order unit, e.g. 5.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="PurchaseOrderQuantityUnit",
        description="Order unit (English unit code), e.g. 'PC'. Required with `quantity`.",
        max_length=3,
    )
    gl_account: SAPCode | None = Field(
        default=None, alias="GLAccount", description="G/L account, e.g. '61010000'.", max_length=10
    )
    cost_center: SAPCode | None = Field(
        default=None, alias="CostCenter", description="Cost center that is charged.", max_length=10
    )
    internal_order: SAPCode | None = Field(
        default=None, alias="InternalOrder", description="Internal or maintenance order that is charged.", max_length=12
    )
    wbs_element: SAPCode | None = Field(
        default=None, alias="WBSElement", description="WBS element that is charged.", max_length=24
    )
    sales_order: SAPCode | None = Field(
        default=None, alias="SalesOrder", description="Sales order that is charged.", max_length=10
    )
    sales_order_item: Numc6 | None = Field(
        default=None, alias="SalesOrderItem", description="Item of the sales order (6 digits, padded)."
    )
    master_fixed_asset: SAPCode | None = Field(
        default=None, alias="MasterFixedAsset", description="Fixed asset (main number) that is charged.", max_length=12
    )
    fixed_asset: SAPCode | None = Field(
        default=None, alias="FixedAsset", description="Sub-number of the fixed asset, e.g. '0'.", max_length=4
    )
    profit_center: SAPCode | None = Field(
        default=None, alias="ProfitCenter", description="Profit center.", max_length=10
    )
    controlling_area: SAPCode | None = Field(
        default=None, alias="ControllingArea", description="Controlling area, e.g. '1000'.", max_length=4
    )
    business_area: SAPCode | None = Field(
        default=None, alias="BusinessArea", description="Business area.", max_length=4
    )
    tax_code: SAPCode | None = Field(
        default=None,
        alias="TaxCode",
        description="Tax code, e.g. 'V1' - system specific; copy from an existing invoice if unsure.",
        max_length=2,
    )
    is_unplanned: bool | None = Field(
        default=None,
        alias="AccountAssignmentIsUnplanned",
        description="True if the account assignment is not in the purchase order (unplanned).",
    )
    text: str | None = Field(
        default=None,
        alias="SuplrInvcAccountAssignmentText",
        description="Text of the account assignment.",
        max_length=50,
    )


class SAPSupplierInvoiceMaterialItemModel(SAPODataCreateModel):
    """An item of a new SAP supplier invoice posted directly to a material - without purchase order (API_SUPPLIERINVOICE_PROCESS_SRV).

    Changes the stock value of the material (e.g. subsequent costs of a stock material).

    """

    item: Numc6 = Field(
        default="1",
        alias="SupplierInvoiceItem",
        description="Item number (6 digits, padded), e.g. 1 -> '000001'. Unique within the material items.",
    )
    material: SAPCode = Field(
        alias="Material",
        description="Material (product) number, e.g. 'PUMP-SEAL-50'; see get_products().",
        min_length=1,
        max_length=40,
    )
    valuation_area: SAPCode = Field(
        alias="ValuationArea",
        description="Valuation area of the material - usually the plant, e.g. '1010'.",
        min_length=1,
        max_length=4,
    )
    valuation_type: SAPCode | None = Field(
        default=None,
        alias="InventoryValuationType",
        description="Valuation type - only for materials with split valuation.",
        max_length=10,
    )
    amount: SAPDecimal = Field(
        alias="SupplierInvoiceItemAmount",
        description="Amount of the item in the document currency, e.g. 100.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Same as the invoice.",
    )
    quantity: SAPDecimal | None = Field(
        default=None,
        alias="Quantity",
        description="Quantity in `unit`, e.g. 10.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="QuantityUnit",
        description="Unit of the quantity (English unit code), e.g. 'PC'. Required with `quantity`.",
        max_length=3,
    )
    debit_credit_code: Literal["S", "H"] | None = Field(
        default=None,
        alias="DebitCreditCode",
        description="'S' debit (default for invoices) or 'H' credit.",
    )
    tax_code: SAPCode | None = Field(
        default=None,
        alias="TaxCode",
        description="Tax code, e.g. 'V1' - system specific; copy from an existing invoice if unsure.",
        max_length=2,
    )
    tax_jurisdiction: SAPCode | None = Field(
        default=None, alias="TaxJurisdiction", description="Tax jurisdiction (US sales tax).", max_length=15
    )
    is_not_cash_discount_liable: bool | None = Field(
        default=None, alias="IsNotCashDiscountLiable", description="True if no cash discount applies to the item."
    )


class SAPSupplierInvoiceAssetItemModel(SAPODataCreateModel):
    """An item of a new SAP supplier invoice posted directly to a fixed asset (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    item: Numc4 = Field(
        default="1",
        alias="SupplierInvoiceItem",
        description="Item number (4 digits, padded), e.g. 1 -> '0001'. Unique within the asset items.",
    )
    company_code: SAPCode = Field(
        alias="CompanyCode", description="Company code of the asset, e.g. '1010'.", min_length=1, max_length=4
    )
    master_fixed_asset: SAPCode = Field(
        alias="MasterFixedAsset",
        description="Fixed asset (main number), e.g. '10000001'.",
        min_length=1,
        max_length=12,
    )
    fixed_asset: SAPCode = Field(
        default="0", alias="FixedAsset", description="Sub-number of the fixed asset, e.g. '0'.", max_length=4
    )
    amount: SAPDecimal = Field(
        alias="SupplierInvoiceItemAmount",
        description="Amount of the item in the document currency, e.g. 5000.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Same as the invoice.",
    )
    debit_credit_code: Literal["S", "H"] | None = Field(
        default=None,
        alias="DebitCreditCode",
        description="'S' debit (default for invoices) or 'H' credit.",
    )
    asset_value_date: ODataV2Date = Field(
        default=None,
        alias="AssetValueDate",
        description="Asset value date (capitalization date), e.g. '2026-11-02'. Defaults to the posting date.",
    )
    profit_center: SAPCode | None = Field(
        default=None, alias="ProfitCenter", description="Profit center.", max_length=10
    )
    tax_code: SAPCode | None = Field(
        default=None,
        alias="TaxCode",
        description="Tax code, e.g. 'V1' - system specific; copy from an existing invoice if unsure.",
        max_length=2,
    )
    tax_jurisdiction: SAPCode | None = Field(
        default=None, alias="TaxJurisdiction", description="Tax jurisdiction (US sales tax).", max_length=15
    )
    assignment_reference: str | None = Field(
        default=None, alias="AssignmentReference", description="Assignment (sort key) in accounting.", max_length=18
    )
    text: str | None = Field(
        default=None, alias="SupplierInvoiceItemText", description="Text of the item.", max_length=50
    )


class SAPSupplierInvoiceWithholdingTaxModel(SAPODataCreateModel):
    """A withholding tax of a new SAP supplier invoice (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    withholding_tax_type: SAPCode = Field(
        alias="WithholdingTaxType",
        description="Withholding tax type of the supplier, e.g. '01' - system specific.",
        min_length=1,
        max_length=2,
    )
    withholding_tax_code: SAPCode | None = Field(
        default=None,
        alias="WithholdingTaxCode",
        description="Withholding tax code, e.g. '01' - system specific.",
        max_length=2,
    )
    base_amount: SAPDecimal | None = Field(
        default=None,
        alias="WithholdingTaxBaseAmount",
        description="Base amount of the withholding tax in the document currency.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    amount: SAPDecimal | None = Field(
        default=None,
        alias="ManuallyEnteredWhldgTaxAmount",
        description="Withholding tax amount - only if not calculated by SAP.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Same as the invoice.",
    )


class SAPSupplierInvoiceSelectedPurchaseOrderModel(SAPODataCreateModel):
    """A purchase order (item) whose open items SAP proposes as invoice items (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    purchase_order: SAPCode = Field(
        alias="PurchaseOrder",
        description="Purchase order, e.g. '4500001540'; see get_purchase_order().",
        min_length=1,
        max_length=10,
    )
    purchase_order_item: Numc5 | None = Field(
        default=None,
        alias="PurchaseOrderItem",
        description="Item of the purchase order (5 digits, padded), e.g. 10 -> '00010'. Omit it for all items.",
    )


class SAPSupplierInvoiceSelectedDeliveryNoteModel(SAPODataCreateModel):
    """A delivery note whose goods receipts SAP proposes as invoice items (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    delivery_note: str = Field(
        alias="InboundDeliveryNote",
        description="Delivery note number of the supplier (as entered at the goods receipt), e.g. 'DN-4711'.",
        min_length=1,
        max_length=16,
    )


class SAPSupplierInvoiceSelectedServiceEntrySheetModel(SAPODataCreateModel):
    """A service entry sheet (item) whose services SAP proposes as invoice items (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    service_entry_sheet: SAPCode = Field(
        alias="ServiceEntrySheet",
        description="Service entry sheet, e.g. '1000000123'.",
        min_length=1,
        max_length=10,
    )
    service_entry_sheet_item: Numc5 | None = Field(
        default=None,
        alias="ServiceEntrySheetItem",
        description="Item of the service entry sheet (5 digits, padded), e.g. 10 -> '00010'. Omit it for all items.",
    )


class SAPSupplierInvoiceAdditionalDataModel(SAPODataCreateModel):
    """Name, address and bank details of a one-time supplier (API_SUPPLIERINVOICE_PROCESS_SRV).

    Only for invoices of a one-time supplier account (the invoicing party has no master data
    of its own).

    """

    name: str = Field(
        alias="InvoicingPartyName1",
        description="Name of the supplier, e.g. 'Quick Repair Ltd.'.",
        min_length=1,
        max_length=35,
    )
    name_2: str | None = Field(
        default=None, alias="InvoicingPartyName2", description="Second line of the name.", max_length=35
    )
    street: str | None = Field(
        default=None, alias="StreetAddressName", description="Street and house number.", max_length=35
    )
    postal_code: SAPCode | None = Field(default=None, alias="PostalCode", description="Postal code.", max_length=10)
    city: str | None = Field(default=None, alias="CityName", description="City.", max_length=35)
    region: SAPCode | None = Field(
        default=None, alias="Region", description="Region (state, province), e.g. 'TX'.", max_length=3
    )
    country: SAPCode | None = Field(
        default=None, alias="Country", description="Country key (ISO), e.g. 'US'.", max_length=3
    )
    language: SAPCode | None = Field(
        default=None, alias="LanguageCode", description="Language key, e.g. 'EN'.", max_length=2
    )
    email: str | None = Field(
        default=None, alias="OneTimeBusinessPartnerEmail", description="E-mail address of the supplier.", max_length=130
    )
    iban: SAPCode | None = Field(
        default=None, alias="IBAN", description="IBAN of the supplier's bank account.", max_length=34
    )
    swift_code: SAPCode | None = Field(
        default=None, alias="SWIFTCode", description="SWIFT / BIC of the bank.", max_length=11
    )
    bank: SAPCode | None = Field(default=None, alias="Bank", description="Bank key (bank number).", max_length=15)
    bank_account: SAPCode | None = Field(
        default=None, alias="BankAccount", description="Bank account number.", max_length=18
    )
    bank_country: SAPCode | None = Field(
        default=None, alias="BankCountry", description="Country key of the bank, e.g. 'US'.", max_length=3
    )
    vat_registration: SAPCode | None = Field(
        default=None, alias="VATRegistration", description="VAT registration number of the supplier.", max_length=20
    )
    tax_id: SAPCode | None = Field(
        default=None, alias="TaxID1", description="Tax number 1 of the supplier.", max_length=16
    )
    is_natural_person: bool | None = Field(
        default=None, alias="IsNaturalPerson", description="True if the supplier is a natural person."
    )


class SAPSupplierInvoicePurchaseOrderItemModel(SAPODataCreateModel):
    """An item of an SAP supplier invoice that refers to a purchase order item (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    item: Numc6 = Field(
        default="1",
        alias="SupplierInvoiceItem",
        description="Item number (6 digits, padded), e.g. 1 -> '000001'. Unique within the invoice.",
    )
    purchase_order: SAPCode = Field(
        alias="PurchaseOrder",
        description="Purchase order that is invoiced, e.g. '4500001540'; see get_purchase_order().",
        min_length=1,
        max_length=10,
    )
    purchase_order_item: Numc5 = Field(
        alias="PurchaseOrderItem",
        description="Item of the purchase order (5 digits, padded), e.g. 10 -> '00010'.",
    )
    amount: SAPDecimal = Field(
        alias="SupplierInvoiceItemAmount",
        description="Net amount of the item in the document currency, e.g. 250.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Same as the invoice.",
    )
    quantity: SAPDecimal | None = Field(
        default=None,
        alias="QuantityInPurchaseOrderUnit",
        description="Invoiced quantity in the order unit (greater than 0), e.g. 10.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="PurchaseOrderQuantityUnit",
        description="Order unit (English unit code), e.g. 'PC' (piece). Required with `quantity`.",
        max_length=3,
    )
    plant: SAPCode | None = Field(
        default=None, alias="Plant", description="Plant of the purchase order item, e.g. '1010'.", max_length=4
    )
    tax_code: SAPCode | None = Field(
        default=None,
        alias="TaxCode",
        description="Tax code, e.g. 'V1' - system specific; copy from an existing invoice if unsure.",
        max_length=2,
    )
    reference_document: SAPCode | None = Field(
        default=None,
        alias="ReferenceDocument",
        description=(
            "Goods receipt (material document) the item refers to - required (with year and item) if the purchase "
            "order item uses goods-receipt-based invoice verification (InvoiceIsGoodsReceiptBased)."
        ),
        max_length=10,
    )
    reference_document_fiscal_year: str | None = Field(
        default=None,
        alias="ReferenceDocumentFiscalYear",
        description="Year of the goods receipt material document, e.g. '2026'.",
        max_length=4,
    )
    reference_document_item: Numc4 | None = Field(
        default=None,
        alias="ReferenceDocumentItem",
        description="Item of the goods receipt material document (4 digits, padded), e.g. 1 -> '0001'.",
    )
    text: str | None = Field(
        default=None, alias="SupplierInvoiceItemText", description="Text of the item.", max_length=50
    )
    price_quantity: SAPDecimal | None = Field(
        default=None,
        alias="QtyInPurchaseOrderPriceUnit",
        description="Invoiced quantity in the order price unit - only if it differs from the order unit.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    price_unit: SAPCode | None = Field(
        default=None,
        alias="PurchaseOrderPriceUnit",
        description="Order price unit (English unit code). Required with `price_quantity`.",
        max_length=3,
    )
    tax_jurisdiction: SAPCode | None = Field(
        default=None, alias="TaxJurisdiction", description="Tax jurisdiction (US sales tax).", max_length=15
    )
    is_subsequent_debit_credit: Literal["X"] | None = Field(
        default=None,
        alias="IsSubsequentDebitCredit",
        description="'X' for a subsequent debit / credit (price difference without quantity).",
    )
    is_finally_invoiced: bool | None = Field(
        default=None,
        alias="IsFinallyInvoiced",
        description="True if no further invoices are expected for the purchase order item (final invoice).",
    )
    is_not_cash_discount_liable: bool | None = Field(
        default=None, alias="IsNotCashDiscountLiable", description="True if no cash discount applies to the item."
    )
    delivery_cost_condition_type: SAPCode | None = Field(
        default=None,
        alias="SuplrInvcDeliveryCostCndnType",
        description="Condition type of a planned delivery cost of the purchase order, e.g. 'FRB1' (freight) - invoices the delivery cost instead of the goods.",
        max_length=4,
    )
    delivery_cost_condition_step: SAPCode | None = Field(
        default=None,
        alias="SuplrInvcDeliveryCostCndnStep",
        description="Step number of the planned delivery cost condition in the purchase order.",
        max_length=3,
    )
    delivery_cost_condition_counter: SAPCode | None = Field(
        default=None,
        alias="SuplrInvcDeliveryCostCndnCount",
        description="Counter of the planned delivery cost condition in the purchase order.",
        max_length=3,
    )
    freight_supplier: SAPCode | None = Field(
        default=None,
        alias="FreightSupplier",
        description="Supplier of a planned delivery cost (e.g. the carrier) if not the invoicing party.",
        max_length=10,
    )
    service_entry_sheet: SAPCode | None = Field(
        default=None,
        alias="ServiceEntrySheet",
        description="Service entry sheet the item refers to (service-based invoice verification).",
        max_length=10,
    )
    service_entry_sheet_item: SAPCode | None = Field(
        default=None, alias="ServiceEntrySheetItem", description="Item of the service entry sheet.", max_length=10
    )
    retention_amount: SAPDecimal | None = Field(
        default=None,
        alias="RetentionAmountInDocCurrency",
        description="Retained amount (paid later), in the document currency.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    retention_percentage: SAPDecimal | None = Field(
        default=None,
        alias="RetentionPercentage",
        description="Retention in percent of the item amount, e.g. 5.",
        ge=0,
        le=100,
    )
    retention_due_date: ODataV2Date = Field(
        default=None, alias="RetentionDueDate", description="Due date of the retained amount, e.g. '2027-11-02'."
    )
    account_assignments: list[SAPSupplierInvoiceAccountAssignmentModel] = Field(
        default_factory=list,
        alias="to_SupplierInvoiceItmAcctAssgmt",
        description="Account assignments of the item - for purchase order items with account assignment (e.g. cost center).",
        exclude_if=is_empty,
    )

    @model_validator(mode="after")
    def check_account_assignments(self) -> Self:
        """Fill in the item number for the account assignments (part of their key)."""

        for account_assignment in self.account_assignments:
            account_assignment.item = self.item

        return self

    # end method definition


class SAPSupplierInvoiceGLAccountItemModel(SAPODataCreateModel):
    """An item of an SAP supplier invoice posted directly to a G/L account (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    item: Numc4 = Field(
        default="1",
        alias="SupplierInvoiceItem",
        description="Item number (4 digits, padded), e.g. 1 -> '0001'. Unique within the G/L account items.",
    )
    gl_account: SAPCode = Field(
        alias="GLAccount", description="G/L account to post to, e.g. '61010000'.", min_length=1, max_length=10
    )
    amount: SAPDecimal = Field(
        alias="SupplierInvoiceItemAmount",
        description="Amount of the item in the document currency, e.g. 100.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Same as the invoice.",
    )
    debit_credit_code: Literal["S", "H"] | None = Field(
        default=None,
        alias="DebitCreditCode",
        description="'S' debit (default for invoices) or 'H' credit.",
    )
    company_code: SAPCode | None = Field(
        default=None, alias="CompanyCode", description="Company code, e.g. '1010'.", max_length=4
    )
    cost_center: SAPCode | None = Field(
        default=None, alias="CostCenter", description="Cost center that is charged.", max_length=10
    )
    profit_center: SAPCode | None = Field(
        default=None, alias="ProfitCenter", description="Profit center.", max_length=10
    )
    internal_order: SAPCode | None = Field(
        default=None, alias="InternalOrder", description="Internal order that is charged.", max_length=12
    )
    wbs_element: SAPCode | None = Field(
        default=None, alias="WBSElement", description="WBS element that is charged.", max_length=24
    )
    tax_code: SAPCode | None = Field(
        default=None,
        alias="TaxCode",
        description="Tax code, e.g. 'V1' - system specific; copy from an existing invoice if unsure.",
        max_length=2,
    )
    text: str | None = Field(
        default=None, alias="SupplierInvoiceItemText", description="Text of the item.", max_length=50
    )
    controlling_area: SAPCode | None = Field(
        default=None, alias="ControllingArea", description="Controlling area, e.g. '1000'.", max_length=4
    )
    business_area: SAPCode | None = Field(
        default=None, alias="BusinessArea", description="Business area.", max_length=4
    )
    functional_area: SAPCode | None = Field(
        default=None, alias="FunctionalArea", description="Functional area.", max_length=16
    )
    sales_order: SAPCode | None = Field(
        default=None, alias="SalesOrder", description="Sales order that is charged.", max_length=10
    )
    sales_order_item: Numc6 | None = Field(
        default=None, alias="SalesOrderItem", description="Item of the sales order (6 digits, padded)."
    )
    activity_type: SAPCode | None = Field(
        default=None, alias="CostCtrActivityType", description="Activity type of the cost center.", max_length=6
    )
    personnel_number: SAPCode | None = Field(
        default=None, alias="PersonnelNumber", description="Personnel number (e.g. for travel costs).", max_length=8
    )
    quantity: SAPDecimal | None = Field(
        default=None,
        alias="Quantity",
        description="Quantity in `unit`, e.g. 10.",
        gt=0,
        max_digits=13,
        decimal_places=3,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="QuantityUnit",
        description="Unit of the quantity (English unit code), e.g. 'PC'. Required with `quantity`.",
        max_length=3,
    )
    tax_jurisdiction: SAPCode | None = Field(
        default=None, alias="TaxJurisdiction", description="Tax jurisdiction (US sales tax).", max_length=15
    )
    tax_base_amount: SAPDecimal | None = Field(
        default=None,
        alias="TaxBaseAmountInTransCrcy",
        description="Base amount for the tax in the document currency - only if it differs from the item amount.",
        ge=0,
        max_digits=16,
        decimal_places=3,
    )
    assignment_reference: str | None = Field(
        default=None, alias="AssignmentReference", description="Assignment (sort key) in accounting.", max_length=18
    )
    is_not_cash_discount_liable: bool | None = Field(
        default=None, alias="IsNotCashDiscountLiable", description="True if no cash discount applies to the item."
    )


class SAPSupplierInvoiceTaxModel(SAPODataCreateModel):
    """A tax line of an SAP supplier invoice - needed if the tax is not calculated automatically (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    tax_code: SAPCode = Field(
        alias="TaxCode",
        description="Tax code, e.g. 'V1' - system specific; copy from an existing invoice if unsure.",
        min_length=1,
        max_length=2,
    )
    tax_amount: SAPDecimal = Field(
        alias="TaxAmount",
        description="Tax amount in the document currency, e.g. 47.50.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    tax_base_amount: SAPDecimal | None = Field(
        default=None,
        alias="TaxBaseAmountInTransCrcy",
        description="Base amount the tax is calculated on, e.g. 250.",
        ge=0,
        max_digits=16,
        decimal_places=3,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="DocumentCurrency",
        description="Document currency (ISO 4217 code), e.g. 'EUR'. Same as the invoice.",
    )
    tax_jurisdiction: SAPCode | None = Field(
        default=None, alias="TaxJurisdiction", description="Tax jurisdiction (US sales tax).", max_length=15
    )
    tax_country: SAPCode | None = Field(
        default=None,
        alias="TaxCountry",
        description="Tax country (ISO), if it differs from the company code's.",
        max_length=3,
    )
    tax_determination_date: ODataV2Date = Field(
        default=None, alias="TaxDeterminationDate", description="Date that determines the tax rate, e.g. '2026-11-02'."
    )


class SAPSupplierInvoiceModel(SAPODataCreateModel):
    """Data to create (post) an SAP supplier invoice (API_SUPPLIERINVOICE_PROCESS_SRV, OData V2).

    Logistics invoice verification: the invoice of a supplier, usually for purchase
    order items (`purchase_order_items`) and / or posted to G/L accounts
    (`gl_account_items`), materials (`material_items`) or fixed assets
    (`asset_items`). Instead of giving the items, purchase orders, delivery notes or
    service entry sheets can be selected - SAP then proposes their open items (only when
    the invoice is posted directly, not together with `purchase_order_items`).
    The invoice is posted directly or parked (`status` 'A') and posted later
    (SAP.post_supplier_invoice()). The invoice number and fiscal year are assigned by SAP.

    See: https://api.sap.com/api/API_SUPPLIERINVOICE_PROCESS_SRV/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "CompanyCode": "1010",
                    "DocumentDate": "2026-11-02",
                    "PostingDate": "2026-11-02",
                    "SupplierInvoiceIDByInvcgParty": "INV-2026-0815",
                    "InvoicingParty": "10300001",
                    "DocumentCurrency": "EUR",
                    "InvoiceGrossAmount": 297.5,
                    "TaxIsCalculatedAutomatically": True,
                    "to_SuplrInvcItemPurOrdRef": [
                        {
                            "PurchaseOrder": "4500001540",
                            "PurchaseOrderItem": "10",
                            "SupplierInvoiceItemAmount": 250,
                            "QuantityInPurchaseOrderUnit": 10,
                            "PurchaseOrderQuantityUnit": "ST",
                            "TaxCode": "V1",
                        }
                    ],
                }
            ]
        }
    )

    company_code: SAPCode = Field(
        alias="CompanyCode",
        description="Company code that receives the invoice, e.g. '1010'.",
        min_length=1,
        max_length=4,
    )
    document_date: ODataV2Date = Field(
        alias="DocumentDate", description="Invoice date (as printed on the invoice), e.g. '2026-11-02'."
    )
    posting_date: ODataV2Date = Field(alias="PostingDate", description="Posting date in accounting, e.g. '2026-11-02'.")
    supplier_invoice_reference: str | None = Field(
        default=None,
        alias="SupplierInvoiceIDByInvcgParty",
        description="The supplier's invoice number (reference), e.g. 'INV-2026-0815'.",
        max_length=16,
    )
    invoicing_party: SAPCode | None = Field(
        default=None,
        alias="InvoicingParty",
        description="Supplier who sends the invoice, e.g. '10300001'. Defaults to the supplier of the purchase order.",
        max_length=10,
    )
    currency: SAPCurrency = Field(
        alias="DocumentCurrency", description="Document currency (ISO 4217 code), e.g. 'EUR'."
    )
    gross_amount: SAPDecimal = Field(
        alias="InvoiceGrossAmount",
        description="Gross amount of the invoice (incl. tax), e.g. 297.50.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    tax_is_calculated_automatically: bool | None = Field(
        default=None,
        alias="TaxIsCalculatedAutomatically",
        description="True to let SAP calculate the tax from the tax codes of the items (otherwise give `taxes`).",
    )
    is_credit_memo: SAPFlagV2 = Field(
        default=None,
        alias="SupplierInvoiceIsCreditMemo",
        description="True for a credit memo of the supplier (instead of an invoice).",
    )
    header_text: str | None = Field(
        default=None, alias="DocumentHeaderText", description="Header text of the invoice.", max_length=25
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="PaymentTerms",
        description="Terms of payment key, e.g. '0001'. Defaults to the supplier's terms - system specific.",
        max_length=4,
    )
    due_calculation_base_date: ODataV2Date = Field(
        default=None,
        alias="DueCalculationBaseDate",
        description="Baseline date for the payment terms, e.g. '2026-11-02'. Defaults to the document date.",
    )
    payment_blocking_reason: SAPCode | None = Field(
        default=None,
        alias="PaymentBlockingReason",
        description="Payment block, e.g. 'R' (invoice verification) - system specific.",
        max_length=1,
    )
    payment_reference: str | None = Field(
        default=None, alias="PaymentReference", description="Payment reference.", max_length=30
    )
    assignment_reference: str | None = Field(
        default=None, alias="AssignmentReference", description="Assignment (sort key) in accounting.", max_length=18
    )
    accounting_document_type: SAPCode | None = Field(
        default=None,
        alias="AccountingDocumentType",
        description="Accounting document type, e.g. 'RE' (invoice) - system specific.",
        max_length=2,
    )
    status: Literal["A"] | None = Field(
        default=None,
        alias="SupplierInvoiceStatus",
        description=(
            "'A' to park the invoice (save it without posting - post it later). Omit it to post the invoice directly."
        ),
    )
    invoice_receipt_date: ODataV2Date = Field(
        default=None, alias="InvoiceReceiptDate", description="Date the invoice was received, e.g. '2026-11-03'."
    )
    invoice_reference: SAPCode | None = Field(
        default=None,
        alias="InvoiceReference",
        description="Supplier invoice the credit memo / subsequent debit refers to, e.g. '5105600123'.",
        max_length=10,
    )
    invoice_reference_fiscal_year: str | None = Field(
        default=None,
        alias="InvoiceReferenceFiscalYear",
        description="Fiscal year of `invoice_reference`, e.g. '2026'.",
        max_length=4,
    )
    unplanned_delivery_cost: SAPDecimal | None = Field(
        default=None,
        alias="UnplannedDeliveryCost",
        description="Unplanned delivery costs (e.g. freight not in the purchase order) in the document currency.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    unplanned_delivery_cost_tax_code: SAPCode | None = Field(
        default=None,
        alias="UnplannedDeliveryCostTaxCode",
        description="Tax code of the unplanned delivery costs - system specific.",
        max_length=2,
    )
    cash_discount_1_percent: SAPDecimal | None = Field(
        default=None,
        alias="CashDiscount1Percent",
        description="Cash discount percentage 1 (overrides the payment terms), e.g. 2.",
        ge=0,
        le=100,
    )
    cash_discount_1_days: SAPDecimal | None = Field(
        default=None, alias="CashDiscount1Days", description="Days for cash discount 1, e.g. 14.", ge=0, le=999
    )
    cash_discount_2_percent: SAPDecimal | None = Field(
        default=None, alias="CashDiscount2Percent", description="Cash discount percentage 2, e.g. 1.", ge=0, le=100
    )
    cash_discount_2_days: SAPDecimal | None = Field(
        default=None, alias="CashDiscount2Days", description="Days for cash discount 2, e.g. 30.", ge=0, le=999
    )
    net_payment_days: SAPDecimal | None = Field(
        default=None, alias="NetPaymentDays", description="Days until the net payment is due, e.g. 60.", ge=0, le=999
    )
    manual_cash_discount: SAPDecimal | None = Field(
        default=None,
        alias="ManualCashDiscount",
        description="Cash discount amount in the document currency - instead of the percentage.",
        ge=0,
        max_digits=14,
        decimal_places=3,
    )
    fixed_cash_discount: Literal["X"] | None = Field(
        default=None, alias="FixedCashDiscount", description="'X' if the cash discount terms are fixed."
    )
    payment_method: SAPCode | None = Field(
        default=None,
        alias="PaymentMethod",
        description="Payment method, e.g. 'T' (bank transfer) - system specific. Defaults to the supplier's.",
        max_length=1,
    )
    payment_method_supplement: SAPCode | None = Field(
        default=None, alias="PaymentMethodSupplement", description="Payment method supplement.", max_length=2
    )
    payment_reason: SAPCode | None = Field(
        default=None, alias="PaymentReason", description="Payment reason - system specific.", max_length=4
    )
    supplier_bank_type: SAPCode | None = Field(
        default=None,
        alias="BPBankAccountInternalID",
        description="Bank type (partner bank) of the supplier to pay to - if the supplier has several bank accounts.",
        max_length=4,
    )
    house_bank: SAPCode | None = Field(
        default=None, alias="HouseBank", description="Own house bank that pays the invoice.", max_length=5
    )
    house_bank_account: SAPCode | None = Field(
        default=None, alias="HouseBankAccount", description="Account at the house bank.", max_length=5
    )
    exchange_rate: SAPDecimal | None = Field(
        default=None,
        alias="DirectQuotedExchangeRate",
        description="Exchange rate (direct quotation) for a foreign currency invoice. Defaults to the current rate.",
        gt=0,
    )
    supplier_vat_registration: SAPCode | None = Field(
        default=None,
        alias="SupplierVATRegistration",
        description="VAT registration number of the supplier (as printed on the invoice).",
        max_length=20,
    )
    supplying_country: SAPCode | None = Field(
        default=None, alias="SupplyingCountry", description="Country the goods are supplied from (ISO).", max_length=3
    )
    tax_determination_date: ODataV2Date = Field(
        default=None, alias="TaxDeterminationDate", description="Date that determines the tax rates."
    )
    tax_reporting_date: ODataV2Date = Field(
        default=None, alias="TaxReportingDate", description="Date for the tax return (tax reporting date)."
    )
    business_area: SAPCode | None = Field(
        default=None, alias="BusinessArea", description="Business area.", max_length=4
    )
    business_place: SAPCode | None = Field(
        default=None, alias="BusinessPlace", description="Business place (tax reporting).", max_length=4
    )
    supplier_line_item_text: str | None = Field(
        default=None,
        alias="SupplierPostingLineItemText",
        description="Text of the supplier line item in accounting.",
        max_length=50,
    )
    is_capital_goods_related: bool | None = Field(
        default=None, alias="SuplrInvcIsCapitalGoodsRelated", description="True if the invoice is for capital goods."
    )
    is_eu_triangular_deal: bool | None = Field(
        default=None, alias="IsEUTriangularDeal", description="True for an EU triangular deal."
    )
    purchase_order_items: Annotated[list[SAPSupplierInvoicePurchaseOrderItemModel], unique_numbers("item")] = Field(
        default_factory=list,
        alias="to_SuplrInvcItemPurOrdRef",
        description=(
            "Items that refer to purchase order items. Item numbers must be unique. Give either these items or "
            "selected documents (selected_purchase_orders, selected_delivery_notes or "
            "selected_service_entry_sheets) - SAP rejects an invoice with both."
        ),
        exclude_if=is_empty,
    )
    gl_account_items: Annotated[list[SAPSupplierInvoiceGLAccountItemModel], unique_numbers("item")] = Field(
        default_factory=list,
        alias="to_SupplierInvoiceItemGLAcct",
        description="Items posted directly to G/L accounts (e.g. costs without purchase order). Item numbers must be unique.",
        exclude_if=is_empty,
    )
    material_items: Annotated[list[SAPSupplierInvoiceMaterialItemModel], unique_numbers("item")] = Field(
        default_factory=list,
        alias="to_SuplrInvcItemMaterial",
        description="Items posted directly to materials (without purchase order). Item numbers must be unique.",
        exclude_if=is_empty,
    )
    asset_items: Annotated[list[SAPSupplierInvoiceAssetItemModel], unique_numbers("item")] = Field(
        default_factory=list,
        alias="to_SuplrInvcItemAsset",
        description="Items posted directly to fixed assets. Item numbers must be unique.",
        exclude_if=is_empty,
    )
    taxes: list[SAPSupplierInvoiceTaxModel] = Field(
        default_factory=list,
        alias="to_SupplierInvoiceTax",
        description="Tax lines - only if the tax is not calculated automatically.",
        exclude_if=is_empty,
    )
    withholding_taxes: list[SAPSupplierInvoiceWithholdingTaxModel] = Field(
        default_factory=list,
        alias="to_SupplierInvoiceWhldgTax",
        description="Withholding taxes - for suppliers subject to withholding tax.",
        exclude_if=is_empty,
    )
    selected_purchase_orders: list[SAPSupplierInvoiceSelectedPurchaseOrderModel] = Field(
        default_factory=list,
        alias="to_SelectedPurchaseOrders",
        description=(
            "Purchase orders (items) whose open items SAP proposes as invoice items - instead of "
            "`purchase_order_items`, only for invoices that are posted directly (a parked invoice gets no items)."
        ),
        exclude_if=is_empty,
    )
    selected_delivery_notes: list[SAPSupplierInvoiceSelectedDeliveryNoteModel] = Field(
        default_factory=list,
        alias="to_SelectedDeliveryNotes",
        description="Delivery notes whose goods receipts SAP proposes as invoice items.",
        exclude_if=is_empty,
    )
    selected_service_entry_sheets: list[SAPSupplierInvoiceSelectedServiceEntrySheetModel] = Field(
        default_factory=list,
        alias="to_SelectedServiceEntrySheets",
        description="Service entry sheets (items) whose services SAP proposes as invoice items.",
        exclude_if=is_empty,
    )
    additional_data: SAPSupplierInvoiceAdditionalDataModel | None = Field(
        default=None,
        alias="to_SuplrInvoiceAdditionalData",
        description="Name, address and bank details of a one-time supplier.",
    )

    @model_validator(mode="after")
    def fill_currency(self) -> Self:
        """Fill in the document currency of the items, account assignments and taxes.

        SAP rejects items without it ("Document currency is missing in item ...") although it is
        the currency of the invoice.

        """

        children = [
            *self.purchase_order_items,
            *(
                account_assignment
                for item in self.purchase_order_items
                for account_assignment in item.account_assignments
            ),
            *self.gl_account_items,
            *self.material_items,
            *self.asset_items,
            *self.taxes,
            *self.withholding_taxes,
        ]
        for child in children:
            child.currency = child.currency or self.currency

        return self

    # end method definition

    @model_validator(mode="after")
    def check_items(self) -> Self:
        """Validate that the invoice has items - or selects the documents SAP proposes the items from."""

        if not any(
            (
                self.purchase_order_items,
                self.gl_account_items,
                self.material_items,
                self.asset_items,
                self.selected_purchase_orders,
                self.selected_delivery_notes,
                self.selected_service_entry_sheets,
            )
        ):
            message = (
                "A supplier invoice needs items (purchase order, G/L account, material or asset items) or selected "
                "purchase orders, delivery notes or service entry sheets"
            )
            raise ValueError(message)

        return self

    # end method definition

    @model_validator(mode="after")
    def check_selected_documents(self) -> Self:
        """Validate the selected purchase orders, delivery notes and service entry sheets.

        Verified in S/4HANA: SAP rejects selected documents together with purchase order items
        (M8/742 "Table 'to_SuplrInvcItemPurOrdRef' must not be filled"), and a parked invoice with
        selected documents is saved without items - it can't be posted later (M8/063).

        """

        if not (self.selected_purchase_orders or self.selected_delivery_notes or self.selected_service_entry_sheets):
            return self

        if self.purchase_order_items:
            message = (
                "Give either purchase_order_items or selected purchase orders / delivery notes / service entry "
                "sheets - SAP rejects both together (M8/742)"
            )
            raise ValueError(message)
        if self.status == "A":
            message = (
                "A parked invoice (status 'A') gets no items from selected purchase orders / delivery notes / service "
                "entry sheets - give purchase_order_items (with the goods receipt as reference_document for "
                "goods-receipt-based invoice verification) or post the invoice directly"
            )
            raise ValueError(message)

        return self

    # end method definition


class SAPSupplierInvoiceAccountAssignmentResponseModel(SAPODataModel):
    """An account assignment of a purchase order item of an SAP supplier invoice as returned by SAP."""

    item: str | None = Field(default=None, alias="SupplierInvoiceItem", description="Item of the supplier invoice.")
    ordinal_number: str | None = Field(
        default=None, alias="OrdinalNumber", description="Sequential number of the account assignment."
    )
    amount: SAPDecimal | None = Field(
        default=None, alias="SuplrInvcAcctAssignmentAmount", description="Amount in the document currency."
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    quantity: SAPDecimal | None = Field(default=None, alias="Quantity", description="Quantity in the order unit.")
    gl_account: str | None = Field(default=None, alias="GLAccount", description="G/L account.")
    cost_center: str | None = Field(default=None, alias="CostCenter", description="Cost center that is charged.")
    internal_order: str | None = Field(default=None, alias="InternalOrder", description="Order that is charged.")
    wbs_element: str | None = Field(default=None, alias="WBSElement", description="WBS element that is charged.")
    sales_order: str | None = Field(default=None, alias="SalesOrder", description="Sales order that is charged.")
    master_fixed_asset: str | None = Field(default=None, alias="MasterFixedAsset", description="Fixed asset.")
    profit_center: str | None = Field(default=None, alias="ProfitCenter", description="Profit center.")
    tax_code: str | None = Field(default=None, alias="TaxCode", description="Tax code.")
    text: str | None = Field(
        default=None, alias="SuplrInvcAccountAssignmentText", description="Text of the account assignment."
    )


class SAPSupplierInvoiceMaterialItemResponseModel(SAPODataModel):
    """A material item of an SAP supplier invoice as returned by SAP (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    item: str | None = Field(default=None, alias="SupplierInvoiceItem", description="Item of the supplier invoice.")
    material: str | None = Field(
        default=None, alias="Material", description="Material (product) number; see get_products()."
    )
    valuation_area: str | None = Field(default=None, alias="ValuationArea", description="Valuation area (plant).")
    amount: SAPDecimal | None = Field(
        default=None, alias="SupplierInvoiceItemAmount", description="Amount of the item in the document currency."
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    quantity: SAPDecimal | None = Field(default=None, alias="Quantity", description="Quantity.")
    unit: str | None = Field(default=None, alias="QuantityUnit", description="Unit of the quantity.")
    debit_credit_code: str | None = Field(default=None, alias="DebitCreditCode", description="'S' debit or 'H' credit.")
    tax_code: str | None = Field(default=None, alias="TaxCode", description="Tax code.")


class SAPSupplierInvoiceAssetItemResponseModel(SAPODataModel):
    """A fixed asset item of an SAP supplier invoice as returned by SAP (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    item: str | None = Field(default=None, alias="SupplierInvoiceItem", description="Item of the supplier invoice.")
    company_code: str | None = Field(default=None, alias="CompanyCode", description="Company code of the asset.")
    master_fixed_asset: str | None = Field(default=None, alias="MasterFixedAsset", description="Fixed asset.")
    fixed_asset: str | None = Field(default=None, alias="FixedAsset", description="Sub-number of the fixed asset.")
    amount: SAPDecimal | None = Field(
        default=None, alias="SupplierInvoiceItemAmount", description="Amount of the item in the document currency."
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    debit_credit_code: str | None = Field(default=None, alias="DebitCreditCode", description="'S' debit or 'H' credit.")
    asset_value_date: ODataDate = Field(default=None, alias="AssetValueDate", description="Asset value date.")
    tax_code: str | None = Field(default=None, alias="TaxCode", description="Tax code.")
    text: str | None = Field(default=None, alias="SupplierInvoiceItemText", description="Text of the item.")


class SAPSupplierInvoiceTaxResponseModel(SAPODataModel):
    """A tax line of an SAP supplier invoice as returned by SAP (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    tax_code: str | None = Field(default=None, alias="TaxCode", description="Tax code.")
    tax_amount: SAPDecimal | None = Field(default=None, alias="TaxAmount", description="Tax amount.")
    tax_base_amount: SAPDecimal | None = Field(
        default=None, alias="TaxBaseAmountInTransCrcy", description="Base amount the tax is calculated on."
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    tax_jurisdiction: str | None = Field(default=None, alias="TaxJurisdiction", description="Tax jurisdiction.")


class SAPSupplierInvoiceWithholdingTaxResponseModel(SAPODataModel):
    """A withholding tax of an SAP supplier invoice as returned by SAP (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    withholding_tax_type: str | None = Field(
        default=None, alias="WithholdingTaxType", description="Withholding tax type."
    )
    withholding_tax_code: str | None = Field(
        default=None, alias="WithholdingTaxCode", description="Withholding tax code."
    )
    base_amount: SAPDecimal | None = Field(
        default=None, alias="WithholdingTaxBaseAmount", description="Base amount of the withholding tax."
    )
    amount: SAPDecimal | None = Field(
        default=None, alias="ManuallyEnteredWhldgTaxAmount", description="Manually entered withholding tax amount."
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")


class SAPSupplierInvoicePurchaseOrderItemResponseModel(SAPODataModel):
    """A purchase order item of an SAP supplier invoice as returned by SAP (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    invoice_id: str = Field(alias="SupplierInvoice", description="Supplier invoice; see get_supplier_invoice().")
    fiscal_year: str = Field(alias="FiscalYear", description="Fiscal year of the supplier invoice.")
    item: str = Field(alias="SupplierInvoiceItem", description="Item of the supplier invoice.")
    purchase_order: str | None = Field(
        default=None, alias="PurchaseOrder", description="Purchase order that is invoiced; see get_purchase_order()."
    )
    purchase_order_item: str | None = Field(
        default=None, alias="PurchaseOrderItem", description="Item of the purchase order."
    )
    amount: SAPDecimal | None = Field(
        default=None, alias="SupplierInvoiceItemAmount", description="Amount of the item in the document currency."
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    quantity: SAPDecimal | None = Field(
        default=None, alias="QuantityInPurchaseOrderUnit", description="Invoiced quantity in the order unit."
    )
    unit: str | None = Field(default=None, alias="PurchaseOrderQuantityUnit", description="Order unit.")
    plant: str | None = Field(
        default=None,
        alias="Plant",
        description="Plant - the site (factory, warehouse, maintenance location) the record belongs to; see get_plants().",
    )
    tax_code: str | None = Field(default=None, alias="TaxCode", description="Tax code.")
    reference_document: str | None = Field(
        default=None, alias="ReferenceDocument", description="Goods receipt (material document) the item refers to."
    )
    reference_document_fiscal_year: str | None = Field(
        default=None, alias="ReferenceDocumentFiscalYear", description="Year of the goods receipt material document."
    )
    reference_document_item: str | None = Field(
        default=None, alias="ReferenceDocumentItem", description="Item of the goods receipt material document."
    )
    text: str | None = Field(default=None, alias="SupplierInvoiceItemText", description="Text of the item.")
    is_finally_invoiced: bool | None = Field(
        default=None, alias="IsFinallyInvoiced", description="True for the final invoice of the purchase order item."
    )
    is_subsequent_debit_credit: str | None = Field(
        default=None, alias="IsSubsequentDebitCredit", description="'X' for a subsequent debit / credit."
    )
    delivery_cost_condition_type: str | None = Field(
        default=None, alias="SuplrInvcDeliveryCostCndnType", description="Condition type of an invoiced delivery cost."
    )
    service_entry_sheet: str | None = Field(
        default=None, alias="ServiceEntrySheet", description="Service entry sheet the item refers to."
    )
    account_assignments: Annotated[
        list[SAPSupplierInvoiceAccountAssignmentResponseModel] | None, BeforeValidator(unwrap_odata_navigation)
    ] = Field(
        default=None,
        alias="to_SupplierInvoiceItmAcctAssgmt",
        description="Account assignments of the item. None if not requested ($expand).",
    )


class SAPSupplierInvoiceGLAccountItemResponseModel(SAPODataModel):
    """A G/L account item of an SAP supplier invoice as returned by SAP (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    invoice_id: str = Field(alias="SupplierInvoice", description="Supplier invoice; see get_supplier_invoice().")
    fiscal_year: str = Field(alias="FiscalYear", description="Fiscal year of the supplier invoice.")
    item: str = Field(alias="SupplierInvoiceItem", description="Item of the supplier invoice.")
    gl_account: str | None = Field(
        default=None, alias="GLAccount", description="G/L account the values are posted to; see get_gl_account()."
    )
    amount: SAPDecimal | None = Field(
        default=None, alias="SupplierInvoiceItemAmount", description="Amount of the item in the document currency."
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    debit_credit_code: str | None = Field(default=None, alias="DebitCreditCode", description="'S' debit or 'H' credit.")
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
    profit_center: str | None = Field(default=None, alias="ProfitCenter", description="Profit center.")
    internal_order: str | None = Field(
        default=None, alias="InternalOrder", description="Internal order that is charged with the costs."
    )
    wbs_element: str | None = Field(
        default=None, alias="WBSElement", description="WBS element that is charged with the costs."
    )
    tax_code: str | None = Field(default=None, alias="TaxCode", description="Tax code.")
    text: str | None = Field(default=None, alias="SupplierInvoiceItemText", description="Text of the item.")


class SAPSupplierInvoiceResponseModel(SAPODataModel):
    """An SAP supplier invoice as returned by SAP (API_SUPPLIERINVOICE_PROCESS_SRV, OData V2).

    A supplier invoice is identified by its number and fiscal year.

    Attributes:
        purchase_order_items / gl_account_items / material_items / asset_items / taxes / withholding_taxes:
            None if they have not been requested ($expand), otherwise a (possibly empty) list.

    """

    invoice_id: str = Field(alias="SupplierInvoice", description="Supplier invoice; see get_supplier_invoice().")
    fiscal_year: str = Field(alias="FiscalYear", description="Fiscal year of the supplier invoice.")
    company_code: str | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code - the legal entity in whose books the transaction is posted; see get_company_codes().",
    )
    document_date: ODataDate = Field(default=None, alias="DocumentDate", description="Invoice date.")
    posting_date: ODataDate = Field(default=None, alias="PostingDate", description="Posting date in accounting.")
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    supplier_invoice_reference: str | None = Field(
        default=None, alias="SupplierInvoiceIDByInvcgParty", description="The supplier's invoice number (reference)."
    )
    invoicing_party: str | None = Field(
        default=None,
        alias="InvoicingParty",
        description="Supplier who sent the invoice - a business partner in the supplier role; see get_suppliers().",
    )
    currency: str | None = Field(default=None, alias="DocumentCurrency", description="Document currency (ISO code).")
    gross_amount: SAPDecimal | None = Field(
        default=None, alias="InvoiceGrossAmount", description="Gross amount of the invoice (incl. tax)."
    )
    header_text: str | None = Field(default=None, alias="DocumentHeaderText", description="Header text.")
    payment_terms: str | None = Field(default=None, alias="PaymentTerms", description="Terms of payment key.")
    due_calculation_base_date: ODataDate = Field(
        default=None, alias="DueCalculationBaseDate", description="Baseline date for the payment terms."
    )
    payment_blocking_reason: str | None = Field(
        default=None, alias="PaymentBlockingReason", description="Payment block (empty if the invoice can be paid)."
    )
    payment_reference: str | None = Field(default=None, alias="PaymentReference", description="Payment reference.")
    status: str | None = Field(
        default=None,
        alias="SupplierInvoiceStatus",
        description="Status of the invoice, e.g. '5' posted, 'A' parked, 'B' parked and complete - system specific.",
    )
    origin: str | None = Field(
        default=None, alias="SupplierInvoiceOrigin", description="Origin of the invoice (how it was entered)."
    )
    is_credit_memo: SAPFlag = Field(
        default=None, alias="SupplierInvoiceIsCreditMemo", description="True for a credit memo of the supplier."
    )
    is_reversed: bool | None = Field(
        default=None, alias="IsReversed", description="True if the invoice has been cancelled (reversed)."
    )
    is_reversal: bool | None = Field(
        default=None, alias="IsReversal", description="True if this document is the reversal of another invoice."
    )
    reverse_document: str | None = Field(
        default=None, alias="ReverseDocument", description="Reversal document (if the invoice has been cancelled)."
    )
    reverse_document_fiscal_year: str | None = Field(
        default=None, alias="ReverseDocumentFiscalYear", description="Fiscal year of the reversal document."
    )
    accounting_document_type: str | None = Field(
        default=None, alias="AccountingDocumentType", description="Accounting document type, e.g. 'RE'."
    )
    invoice_receipt_date: ODataDate = Field(
        default=None, alias="InvoiceReceiptDate", description="Date the invoice was received."
    )
    invoice_reference: str | None = Field(
        default=None, alias="InvoiceReference", description="Supplier invoice a credit memo refers to."
    )
    invoice_reference_fiscal_year: str | None = Field(
        default=None, alias="InvoiceReferenceFiscalYear", description="Fiscal year of `invoice_reference`."
    )
    unplanned_delivery_cost: SAPDecimal | None = Field(
        default=None, alias="UnplannedDeliveryCost", description="Unplanned delivery costs in the document currency."
    )
    cash_discount_1_percent: SAPDecimal | None = Field(
        default=None, alias="CashDiscount1Percent", description="Cash discount percentage 1."
    )
    cash_discount_1_days: SAPDecimal | None = Field(
        default=None, alias="CashDiscount1Days", description="Days for cash discount 1."
    )
    net_payment_days: SAPDecimal | None = Field(
        default=None, alias="NetPaymentDays", description="Days until the net payment is due."
    )
    payment_method: str | None = Field(default=None, alias="PaymentMethod", description="Payment method.")
    house_bank: str | None = Field(default=None, alias="HouseBank", description="House bank that pays the invoice.")
    supplier_vat_registration: str | None = Field(
        default=None, alias="SupplierVATRegistration", description="VAT registration number of the supplier."
    )
    purchase_order_items: Annotated[
        list[SAPSupplierInvoicePurchaseOrderItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)
    ] = Field(
        default=None,
        alias="to_SuplrInvcItemPurOrdRef",
        description="Purchase order items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    gl_account_items: Annotated[
        list[SAPSupplierInvoiceGLAccountItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)
    ] = Field(
        default=None,
        alias="to_SupplierInvoiceItemGLAcct",
        description="G/L account items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    material_items: Annotated[
        list[SAPSupplierInvoiceMaterialItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)
    ] = Field(
        default=None,
        alias="to_SuplrInvcItemMaterial",
        description="Material items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    asset_items: Annotated[
        list[SAPSupplierInvoiceAssetItemResponseModel] | None, BeforeValidator(unwrap_odata_navigation)
    ] = Field(
        default=None,
        alias="to_SuplrInvcItemAsset",
        description="Fixed asset items. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    taxes: Annotated[list[SAPSupplierInvoiceTaxResponseModel] | None, BeforeValidator(unwrap_odata_navigation)] = Field(
        default=None,
        alias="to_SupplierInvoiceTax",
        description="Tax lines. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    withholding_taxes: Annotated[
        list[SAPSupplierInvoiceWithholdingTaxResponseModel] | None, BeforeValidator(unwrap_odata_navigation)
    ] = Field(
        default=None,
        alias="to_SupplierInvoiceWhldgTax",
        description="Withholding taxes. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPSupplierInvoiceQueryModel(SAPODataQueryModel):
    """Search criteria for SAP supplier invoices (API_SUPPLIERINVOICE_PROCESS_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "invoice_id": "FiscalYear {direction},SupplierInvoice {direction}",
        "posting_date": "PostingDate {direction}",
        "document_date": "DocumentDate {direction}",
    }
    EXPAND: ClassVar[str] = (
        "to_SuplrInvcItemPurOrdRef/to_SupplierInvoiceItmAcctAssgmt,to_SupplierInvoiceItemGLAcct,"
        "to_SuplrInvcItemMaterial,to_SuplrInvcItemAsset,to_SupplierInvoiceTax,to_SupplierInvoiceWhldgTax"
    )
    sort_by: Literal["invoice_id", "posting_date", "document_date"] = Field(
        default="invoice_id", description="Sort criterion."
    )
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    invoice_ids: Annotated[list[SAPCode] | None, ODataCondition("SupplierInvoice")] = Field(
        default=None, description="Supplier invoice numbers, e.g. ['5105600123']."
    )
    fiscal_year: Annotated[str | None, ODataCondition("FiscalYear")] = Field(
        default=None, description="Fiscal year of the invoices, e.g. '2026'."
    )
    company_code: Annotated[SAPCode | None, ODataCondition("CompanyCode")] = Field(
        default=None, description="Company code, e.g. '1010'."
    )
    invoicing_party: Annotated[SAPCode | None, ODataCondition("InvoicingParty")] = Field(
        default=None, description="Supplier who sent the invoices."
    )
    supplier_invoice_reference: Annotated[str | None, ODataCondition("SupplierInvoiceIDByInvcgParty")] = Field(
        default=None, description="The supplier's invoice number (reference)."
    )
    statuses: Annotated[list[SAPCode] | None, ODataCondition("SupplierInvoiceStatus")] = Field(
        default=None, description="Invoice statuses, e.g. ['5'] (posted). System specific."
    )
    posting_date_from: Annotated[date | None, ODataCondition("PostingDate", operator="ge")] = Field(
        default=None, description="Only invoices posted on or after this date."
    )
    posting_date_to: Annotated[date | None, ODataCondition("PostingDate", operator="le")] = Field(
        default=None, description="Only invoices posted on or before this date."
    )
    document_date_from: Annotated[date | None, ODataCondition("DocumentDate", operator="ge")] = Field(
        default=None, description="Only invoices dated on or after this date."
    )
    document_date_to: Annotated[date | None, ODataCondition("DocumentDate", operator="le")] = Field(
        default=None, description="Only invoices dated on or before this date."
    )
    is_reversed: Annotated[bool | None, ODataCondition("IsReversed")] = Field(
        default=None, description="False = only invoices that have not been cancelled."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each invoice.")


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
    SetMaintOrdStsToMrkdForDeltn accepts "AssgdMaintNotifIsToBeSetDel" (True also sets the
    deletion flag of the assigned maintenance notification - API_MAINTNOTIFICATION itself
    cannot delete notifications). SAP only accepts it for closed orders - use
    delete_maintenance_order() which closes the order first.

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


class SAPMaintenanceOrderOperationAction(StrEnum):
    """Status actions for maintenance order operations (function imports of API_MAINTENANCEORDER).

    Values (SAP function names) and their effect on the operation:
    * SetMaintOrderOpToDispatched: dispatch the operation (status DSPT) - it is
      planned for execution by its work center at its scheduled dates.
    * ResetMaintOrderOpStsDispatched: undo the dispatching.

    Operations are deleted with delete_maintenance_order_operation().

    """

    DISPATCH = "SetMaintOrderOpToDispatched"
    RESET_DISPATCHED = "ResetMaintOrderOpStsDispatched"


class SAPMaintenanceNotificationAction(StrEnum):
    """Status actions for maintenance notifications (actions of API_MAINTNOTIFICATION).

    Values (SAP function names) and their effect on the notification:
    * CompleteMaintNotification: complete the notification (status NOCO).
    * SetMaintNotifToInProcess: put the notification in process (status NOPR).

    API_MAINTNOTIFICATION has no action to delete a notification (and does not
    allow DELETE). A notification assigned to an order can get the deletion flag
    together with its order - see delete_maintenance_order().

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


class SAPCreditMemoRequestAction(StrEnum):
    """Approval actions for credit memo requests (function imports of API_CREDIT_MEMO_REQUEST_SRV).

    Values (SAP function names) and their effect:
    * releaseApprovalRequest: approve (release) a credit memo request that is in approval.
    * rejectApprovalRequest: reject a credit memo request that is in approval.

    """

    RELEASE_APPROVAL_REQUEST = "releaseApprovalRequest"
    REJECT_APPROVAL_REQUEST = "rejectApprovalRequest"


class SAPOutboundDeliveryAction(StrEnum):
    """Status actions for outbound deliveries (function imports of API_OUTBOUND_DELIVERY_SRV).

    Values (SAP function names) and their effect on the delivery:
    * PickAllItems: pick all items (picking quantity = delivery quantity).
    * ConfirmPickingAllItems: confirm the picking of all items.
    * PostGoodsIssue: post the goods issue - reduces the stock, the delivery can be billed.
    * ReverseGoodsIssue: reverse the goods issue - needs the parameter "ActualGoodsMovementDate".
    * DeleteAllHandlingUnitsFromDelivery: unpack the delivery (delete all handling units).

    Item actions (e.g. "PickOneItem", "ConfirmPickingOneItem") are called the same way
    with the parameter "DeliveryDocumentItem" - see change_outbound_delivery_status().

    """

    PICK_ALL_ITEMS = "PickAllItems"
    CONFIRM_PICKING_ALL_ITEMS = "ConfirmPickingAllItems"
    POST_GOODS_ISSUE = "PostGoodsIssue"
    REVERSE_GOODS_ISSUE = "ReverseGoodsIssue"
    DELETE_ALL_HANDLING_UNITS = "DeleteAllHandlingUnitsFromDelivery"


class SAPInboundDeliveryAction(StrEnum):
    """Status actions for inbound deliveries (function imports of API_INBOUND_DELIVERY_SRV).

    Values (SAP function names) and their effect on the delivery:
    * PutawayAllItems: put away all items (putaway quantity = delivery quantity).
    * ConfirmPutawayAllItems: confirm the putaway of all items.
    * PostGoodsReceipt: post the goods receipt - increases the stock.
    * ReverseGoodsReceipt: reverse the goods receipt - needs the parameter "ActualGoodsMovementDate".

    Item actions (e.g. "PutawayOneItem", "ConfirmPutawayOneItem") are called the same way
    with the parameter "DeliveryDocumentItem" - see change_inbound_delivery_status().

    """

    PUTAWAY_ALL_ITEMS = "PutawayAllItems"
    CONFIRM_PUTAWAY_ALL_ITEMS = "ConfirmPutawayAllItems"
    POST_GOODS_RECEIPT = "PostGoodsReceipt"
    REVERSE_GOODS_RECEIPT = "ReverseGoodsReceipt"


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
        description="Movement type, e.g. '101' (goods receipt for purchase order), '201' (issue to cost center), '261' (issue to order), '311' (transfer) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Entry unit (English unit code, max. 3 characters), e.g. 'PC' (piece) - internal codes like 'ST' are rejected. Defaults to the base unit of the material.",
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
        description="Reason for the movement, e.g. for scrapping or returns - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
    unit: str | None = Field(default=None, alias="EntryUnit", description="Entry unit (English unit code, e.g. 'PC').")
    base_quantity: SAPDecimal | None = Field(
        default=None, alias="QuantityInBaseUnit", description="Quantity in the base unit of the material."
    )
    base_unit: str | None = Field(
        default=None, alias="MaterialBaseUnit", description="Base unit of the material (English unit code, e.g. 'PC')."
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
        description="Supplier (vendor) number - a business partner in the supplier role; see get_suppliers().",
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
    """Search criteria for SAP goods movements / material documents (API_MATERIAL_DOCUMENT_SRV).

    Purchase orders, production orders, materials, plants and movement types are item properties -
    they are resolved via the material document items first (see SAP.iter_goods_movements()).

    """

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
    purchase_orders: list[SAPCode] | None = Field(
        default=None, description="Only material documents with items of these purchase orders, e.g. ['4500001540']."
    )
    production_orders: list[SAPCode] | None = Field(
        default=None, description="Only material documents with items of these production orders, e.g. ['1000161']."
    )
    materials: list[SAPCode] | None = Field(
        default=None, description="Only material documents with items of these materials (products), e.g. ['R-9010']."
    )
    plants: list[SAPCode] | None = Field(
        default=None, description="Only material documents with items in these plants, e.g. ['3000']."
    )
    movement_types: list[SAPCode] | None = Field(
        default=None, description="Only material documents with items of these movement types, e.g. ['101', '261']."
    )
    expand_items: bool = Field(default=False, description="Also return the items of each material document.")

    @property
    def has_item_criteria(self) -> bool:
        """Whether the query has criteria of the material document items (resolved via the items first)."""

        return any((self.purchase_orders, self.production_orders, self.materials, self.plants, self.movement_types))


class SAPGoodsMovementItemQueryModel(SAPODataQueryModel):
    """Search criteria for SAP material document items (API_MATERIAL_DOCUMENT_SRV, A_MaterialDocumentItem).

    Used to find the material documents of purchase orders, production orders, materials, plants
    and movement types (see SAP.iter_goods_movements()).

    """

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "document": "MaterialDocumentYear {direction},MaterialDocument {direction},MaterialDocumentItem asc",
    }
    sort_by: Literal["document"] = Field(default="document", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    purchase_orders: Annotated[list[SAPCode] | None, ODataCondition("PurchaseOrder")] = Field(
        default=None, description="Purchase orders of the items, e.g. ['4500001540']."
    )
    production_orders: Annotated[list[SAPCode] | None, ODataCondition("ManufacturingOrder")] = Field(
        default=None, description="Production orders of the items, e.g. ['1000161']."
    )
    materials: Annotated[list[SAPCode] | None, ODataCondition("Material")] = Field(
        default=None, description="Materials (products) of the items, e.g. ['R-9010']."
    )
    plants: Annotated[list[SAPCode] | None, ODataCondition("Plant")] = Field(
        default=None, description="Plants of the items, e.g. ['3000']."
    )
    movement_types: Annotated[list[SAPCode] | None, ODataCondition("GoodsMovementType")] = Field(
        default=None, description="Movement types of the items, e.g. ['101']."
    )
    document_year: Annotated[SAPCode | None, ODataCondition("MaterialDocumentYear")] = Field(
        default=None, description="Year of the material documents, e.g. '2026'."
    )
    documents: Annotated[list[SAPCode] | None, ODataCondition("MaterialDocument")] = Field(
        default=None, description="Material document numbers, e.g. ['4900000123']."
    )


# ---------------------------------------------------------------------------
# Material stock (API_MATERIAL_STOCK_SRV, OData V2)
# ---------------------------------------------------------------------------

# The stock types of the material stock (InventoryStockType, domain NSDM_LBBSA):
SAP_INVENTORY_STOCK_TYPES: dict[str, str] = {
    "01": "Unrestricted-Use Stock",
    "02": "Stock in Quality Inspection",
    "03": "Returns",
    "04": "Stock Transfer (Storage Location)",
    "05": "Stock Transfer (Plant)",
    "06": "Stock in Transit",
    "07": "Blocked Stock",
    "08": "Restricted-Use Stock",
    "09": "Tied Empties",
    "10": "Valuated Goods Receipt Blocked Stock",
}


class SAPMaterialStockResponseModel(SAPODataModel):
    """The stock of a material in one stock segment as returned by SAP (API_MATERIAL_STOCK_SRV, A_MatlStkInAcctMod).

    A stock segment is the combination of plant, storage location, batch, stock type and special
    stock (e.g. consignment stock of a supplier or the stock of a sales order). SAP keeps segments
    with a quantity of 0 (e.g. after the stock has been issued) - see SAPMaterialStockQueryModel.include_zero.

    """

    material: str = Field(alias="Material", description="Material (product) number; see get_products().")
    plant: str = Field(alias="Plant", description="Plant of the stock; see get_plants().")
    storage_location: str | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location of the stock - empty for stock that is not kept in a storage location (e.g. in transit).",
    )
    batch: str | None = Field(
        default=None, alias="Batch", description="Batch of the stock (batch-managed materials only)."
    )
    stock_type: str | None = Field(
        default=None,
        alias="InventoryStockType",
        description="Stock type, e.g. '01' (unrestricted-use), '02' (quality inspection), '07' (blocked); see stock_type_name.",
    )
    special_stock_type: str | None = Field(
        default=None,
        alias="InventorySpecialStockType",
        description="Special stock type, e.g. 'K' (supplier consignment), 'E' (sales order stock), 'Q' (project stock) - empty for own stock.",
    )
    supplier: str | None = Field(
        default=None, alias="Supplier", description="Supplier of special stock (e.g. consignment stock)."
    )
    customer: str | None = Field(
        default=None, alias="Customer", description="Customer of special stock (e.g. customer consignment)."
    )
    sales_order: str | None = Field(
        default=None, alias="SDDocument", description="Sales order of sales order stock (special stock 'E')."
    )
    sales_order_item: str | None = Field(
        default=None, alias="SDDocumentItem", description="Sales order item of sales order stock."
    )
    wbs_element_internal_id: str | None = Field(
        default=None, alias="WBSElementInternalID", description="Internal ID of the WBS element of project stock."
    )
    quantity: SAPDecimal | None = Field(
        default=None, alias="MatlWrhsStkQtyInMatlBaseUnit", description="Stock quantity in the base unit."
    )
    base_unit: str | None = Field(
        default=None, alias="MaterialBaseUnit", description="Base unit of the material (English unit code, e.g. 'PC')."
    )

    @field_validator("wbs_element_internal_id", "sales_order_item", mode="before")
    @classmethod
    def check_initial_numbers(cls, value: str | None) -> str | None:
        """SAP returns '0' / '000...0' for stock without WBS element or sales order item - read it as None."""

        return value if value and value.strip("0") else None

    # end method definition

    @computed_field
    @property
    def stock_type_name(self) -> str | None:
        """Return the name of the stock type, e.g. 'Blocked Stock'."""

        return SAP_INVENTORY_STOCK_TYPES.get(self.stock_type or "", self.stock_type)

    # end method definition


class SAPMaterialStockQueryModel(SAPODataQueryModel):
    """Search criteria for the SAP material stock (API_MATERIAL_STOCK_SRV, A_MatlStkInAcctMod)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "material": "Material {direction},Plant asc,StorageLocation asc,Batch asc,InventoryStockType asc",
    }
    sort_by: Literal["material"] = Field(default="material", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    materials: Annotated[list[SAPCode] | None, ODataCondition("Material")] = Field(
        default=None, description="Materials (products), e.g. ['R-9010']."
    )
    plants: Annotated[list[SAPCode] | None, ODataCondition("Plant")] = Field(
        default=None, description="Plants, e.g. ['3000']."
    )
    storage_locations: Annotated[list[SAPCode] | None, ODataCondition("StorageLocation")] = Field(
        default=None, description="Storage locations, e.g. ['0001']."
    )
    batches: Annotated[list[SAPCode] | None, ODataCondition("Batch")] = Field(
        default=None, description="Batches, e.g. ['SL2024-07B']."
    )
    stock_types: Annotated[list[SAPCode] | None, ODataCondition("InventoryStockType")] = Field(
        default=None, description="Stock types, e.g. ['01'] (unrestricted-use), ['07'] (blocked)."
    )
    special_stock_types: Annotated[list[SAPCode] | None, ODataCondition("InventorySpecialStockType")] = Field(
        default=None, description="Special stock types, e.g. ['K'] (supplier consignment), [''] = own stock only."
    )
    include_zero: bool = Field(
        default=False,
        description="Also return stock segments with a quantity of 0 - SAP keeps them e.g. after the stock has been issued.",
    )

    def to_odata(self, odata_version: int) -> dict:
        """Return the OData query options - without the segments of quantity 0 unless include_zero is set.

        The segments without stock are filtered by SAP, so that the limit and the paging only count
        segments with stock (in S/4HANA most segments of a plant can have a quantity of 0).

        Args:
            odata_version (int):
                The OData version of the service (2 or 4).

        Returns:
            dict:
                The query options ($filter, $orderby).

        """

        params = super().to_odata(odata_version=odata_version)
        if not self.include_zero:
            condition = "MatlWrhsStkQtyInMatlBaseUnit ne {}".format("0M" if odata_version == 2 else "0")
            params["$filter"] = "{} and {}".format(params["$filter"], condition) if "$filter" in params else condition

        return params

    # end method definition


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
        max_digits=7,
        decimal_places=1,
    )
    actual_work_unit: SAPCode | None = Field(
        default=None,
        alias="ActualWorkQuantityUnit",
        description="Unit of the actual work (English unit code), e.g. 'HR' (hours) - the unit of the operation's planned work.",
        max_length=3,
    )
    actual_duration: SAPDecimal | None = Field(
        default=None,
        alias="ActualDuration",
        description="Actual duration of the operation in `actual_duration_unit`.",
        ge=0,
        max_digits=5,
        decimal_places=1,
    )
    actual_duration_unit: SAPCode | None = Field(
        default=None,
        alias="ActualDurationUnit",
        description="Unit of the actual duration (English unit code), e.g. 'H'.",
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
        max_digits=7,
        decimal_places=1,
    )
    remaining_work_unit: SAPCode | None = Field(
        default=None,
        alias="RemainingWorkQuantityUnit",
        description="Unit of the remaining work (English unit code), e.g. 'H'.",
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
        description="Activity type for cost allocation. Defaults to the activity type of the operation - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Reason for a variance - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Unit of the actual work (English unit code), e.g. 'H'.",
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
        default=None, alias="RemainingWorkQuantityUnit", description="Unit of the remaining work, e.g. 'HR' (hours)."
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
        description="Unit of the cycle as English unit code, e.g. 'MON' (months), 'WK' (weeks), 'DAY' (days), 'YR' (years) or 'H' (operating hours). Internal SAP codes like 'TAG' are rejected.",
        min_length=1,
        max_length=3,
    )
    description: str | None = Field(
        default=None,
        alias="MaintPlanCycleDesc",
        description="Text of the cycle, e.g. 'Quarterly'.",
        max_length=30,
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
    # Mandatory for the item in API_MAINTENANCEPLAN - maintenance items also exist on their own
    # and can only be assigned to a plan of the same category (filled from the plan, see
    # SAPMaintenancePlanModel.check_item_categories()):
    category: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlanCategory",
        description="Maintenance plan category of the item - the same as the plan's category. Omit it to use the plan's category.",
        max_length=2,
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
        description="Task list group describing the work to do - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Maintenance planner group - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=3,
    )
    order_type: SAPCode | None = Field(
        default=None,
        alias="MaintenanceOrderType",
        description="Order type of the generated maintenance orders, e.g. 'PM03' or 'YA03' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=4,
    )
    notification_type: SAPCode | None = Field(
        default=None,
        alias="NotificationType",
        description="Notification type of generated notifications, e.g. 'M1' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=2,
    )
    activity_type: SAPCode | None = Field(
        default=None,
        alias="MaintenanceActivityType",
        description="Maintenance activity type, e.g. '001' (inspection) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Maintenance priority of the generated orders, e.g. '3' - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
                    "SchedulingDuration": 12,
                    "SchedulingDurationUnit": "MON",
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
        description="Maintenance plan category, e.g. 'PM' (maintenance order), 'SM' (service order) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=2,
    )
    strategy: SAPCode | None = Field(
        default=None,
        alias="MaintenanceStrategy",
        description="Maintenance strategy for strategy plans, e.g. 'A'. Omit for single cycle plans (use `cycles`) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
        max_length=6,
    )
    # CallHorizonPercent is an Edm.String with MaxLength 3 in API_MAINTENANCEPLAN (not an Edm.Decimal).
    # It is validated as whole number (80, 80.0 and "80" are accepted, 80.5 is rejected) and always
    # sent as string without decimals, e.g. "80" - SAP rejects values like "80.0":
    call_horizon_percent: Annotated[int, PlainSerializer(str, when_used="json")] | None = Field(
        default=None,
        alias="CallHorizonPercent",
        description="Call horizon in whole percent (0-100): when within the cycle the order is generated, e.g. 80.",
        ge=0,
        le=100,
    )
    # SchedulingDuration is an Edm.String with MaxLength 3 as well - sent as whole number string, e.g. "12":
    scheduling_duration: Annotated[int, PlainSerializer(str, when_used="json")] | None = Field(
        default=None,
        alias="SchedulingDuration",
        description="Scheduling period (0-999 in `scheduling_duration_unit`): how far ahead the calls are scheduled, e.g. 12 (months) or 365 (days).",
        ge=0,
        le=999,
    )
    # The unit is language dependent - pyxecm logs on in English, so SAP expects the English unit
    # codes (checked in S/4HANA: 'DAY', 'D', 'WK', 'MON', 'YR', 'H', 'HR' and 'MIN' are accepted,
    # internal codes like 'TAG' are rejected with /IWBEP/CM_MGW_RT/022 and non-time units like
    # 'KM' with IP/132). Single cycle plans can't be created without it (IP/131):
    scheduling_duration_unit: SAPCode | None = Field(
        default=None,
        alias="SchedulingDurationUnit",
        description="Time unit of the scheduling period as English unit code: 'DAY', 'WK', 'MON' or 'YR'. Required for single cycle plans.",
        max_length=3,
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

    @model_validator(mode="after")
    def check_item_categories(self) -> Self:
        """Fill in the plan category for the items and check that plan and items have the same category.

        SAP requires the category for each item and only assigns items of the plan's category.

        """

        if not self.items:
            return self

        self.category = self.category or next((item.category for item in self.items if item.category), None)
        if not self.category:
            message = "The maintenance plan needs a category, e.g. 'PM'"
            raise ValueError(message)
        for item in self.items:
            item.category = item.category or self.category
        categories = {self.category} | {item.category for item in self.items}
        if len(categories) > 1:
            message = "Maintenance plan and items must have the same category, got -> {}".format(sorted(categories))
            raise ValueError(message)

        return self

    # end method definition

    @model_validator(mode="after")
    def check_scheduling_duration_unit(self) -> Self:
        """Validate that single cycle plans have a unit for the scheduling period (SAP rejects them with IP/131)."""

        if self.cycles and not self.scheduling_duration_unit:
            message = (
                "Single cycle plans need a `scheduling_duration_unit` (time unit of the scheduling period), e.g. 'MON'"
            )
            raise ValueError(message)

        return self

    # end method definition


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
        description="Unit of the cycle (English unit code), e.g. 'MON'.",
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
        alias="MaintenanceItem",
        description="Maintenance item number - unique in the SAP system (not the position in the plan), e.g. '142'.",
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
    planning_plants: list[SAPCode] | None = Field(
        default=None, description="Only plans with items of these maintenance planning plants, e.g. ['3000']."
    )
    functional_location_ids: list[str] | None = Field(
        default=None,
        description="Only plans with items for these functional locations (internal IDs, not the labels shown in the UI).",
    )
    functional_location_labels: list[str] | None = Field(
        default=None,
        description="Only plans with items for these functional locations (labels as shown in the UI, e.g. ['C1-B01-1']).",
    )
    equipment_ids: list[SAPCode] | None = Field(
        default=None, description="Only plans with items for these equipments, e.g. ['210100001']."
    )
    expand_items: bool = Field(default=False, description="Also return the cycles and items of each plan.")

    @property
    def has_item_criteria(self) -> bool:
        """Whether the query has criteria of the maintenance items (resolved via the items first)."""

        return any(
            (self.planning_plants, self.functional_location_ids, self.functional_location_labels, self.equipment_ids)
        )


class SAPMaintenancePlanItemQueryModel(SAPODataQueryModel):
    """Search criteria for SAP maintenance items (API_MAINTENANCEPLAN, MaintenanceItem).

    Used to find the maintenance plans of planning plants, functional locations and equipments
    (see SAP.iter_maintenance_plans()).

    """

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "plan_id": "MaintenancePlan {direction},MaintenanceItem asc",
    }
    sort_by: Literal["plan_id"] = Field(default="plan_id", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(
        default="desc", description="Sort direction, desc = newest / highest first."
    )
    planning_plants: Annotated[list[SAPCode] | None, ODataCondition("MaintenancePlanningPlant")] = Field(
        default=None, description="Maintenance planning plants of the items, e.g. ['3000']."
    )
    functional_location_ids: Annotated[list[str] | None, ODataCondition("FunctionalLocation")] = Field(
        default=None, description="Functional locations of the items (internal IDs)."
    )
    functional_location_labels: Annotated[list[str] | None, ODataCondition("FunctionalLocationLabelName")] = Field(
        default=None, description="Functional locations of the items (labels as shown in the UI)."
    )
    equipment_ids: Annotated[list[SAPCode] | None, ODataCondition("Equipment")] = Field(
        default=None, description="Equipments of the items."
    )
    plan_ids: Annotated[list[SAPCode] | None, ODataCondition("MaintenancePlan")] = Field(
        default=None, description="Maintenance plan numbers."
    )


# ---------------------------------------------------------------------------
# Maintenance task lists (API_MAINTENANCETASKLIST, OData V4)
# ---------------------------------------------------------------------------


class SAPTaskListOperationMaterialModel(SAPODataCreateModel):
    """A material (component) needed by an operation of a new task list - e.g. a spare part.

    SAP allocates the material to the operation via an item of a plant maintenance BOM:
    the BOM of the assembly of a general task list or of the equipment / functional
    location (or its construction type). The material must be an item of this BOM.

    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Material": "the material is given by the BOM item - delete and allocate the material again",
    }

    # Filled with the task list type and operation number (see SAPTaskListModel.assign_operation_keys()) - SAP
    # rejects nested materials without them ("Task list type  is not supported", "Operation  ... not found"):
    task_list_type: SkipJsonSchema[str | None] = Field(default=None, alias="TaskListType")
    operation: SkipJsonSchema[str | None] = Field(default=None, alias="MaintenanceTaskListOperation")
    material: SAPCode = Field(
        alias="Material",
        description="Material (product) number of the component, e.g. 'SEAL-KIT-50' - an item of the BOM of the assembly.",
        min_length=1,
        max_length=40,
    )
    quantity: SAPDecimal = Field(
        alias="BillOfMaterialItemQuantity",
        description="Quantity of the material needed for the operation, e.g. 1.",
        gt=0,
    )
    # OData V4 rejects a quantity without its unit:
    unit: SAPCode = Field(
        alias="BillOfMaterialItemUnit",
        description="Unit of the quantity (English unit code), e.g. 'PC' - the unit of the BOM item.",
        min_length=1,
        max_length=3,
    )
    bom_item: SAPCode | None = Field(
        default=None,
        alias="TaskListOpBOMItmInternalID",
        description=(
            "Internal ID (node number) of the BOM item, e.g. '1' - the item node of the BOM items of "
            "get_material_boms(). "
            "SAP finds the item by the material - only needed if the material is in the BOM several times."
        ),
        max_length=8,
    )


class SAPTaskListOperationModel(SAPODataCreateModel):
    """An operation of an SAP maintenance task list (API_MAINTENANCETASKLIST, OData V4).

    Additional OData properties of the operation that are not modelled here can be
    passed with their OData name (e.g. "CostCtrActivityType").

    """

    # Filled for operations with materials (see SAPTaskListModel.assign_operation_keys()):
    task_list_type: SkipJsonSchema[str | None] = Field(default=None, alias="TaskListType")
    operation: Numc4 = Field(
        default="10",
        alias="MaintenanceTaskListOperation",
        description="Operation number (4 digits, padded), e.g. 10 -> '0010'. Unique within the task list.",
    )
    description: str = Field(
        alias="OperationText",
        description="Short text of the operation, e.g. 'Check pump seal'.",
        min_length=1,
        max_length=40,
    )
    control_key: SAPCode | None = Field(
        default=None,
        alias="OperationControlProfile",
        description="Operation control key, e.g. 'PM01' (internal processing) - system specific; copy from an existing task list if unsure.",
        max_length=4,
    )
    work_center: SAPCode | None = Field(
        default=None,
        alias="WorkCenter",
        description="Work center executing the operation, e.g. 'RES-0100'. Defaults to the work center of the task list.",
        max_length=8,
    )
    plant: SAPCode | None = Field(
        default=None,
        alias="Plant",
        description="Plant of the operation's work center, e.g. '1010'.",
        max_length=4,
    )
    work: SAPDecimal | None = Field(
        default=None,
        alias="OpPlannedWorkQuantity",
        description="Planned work in `work_unit`, e.g. 2.5.",
        ge=0,
    )
    work_unit: SAPCode | None = Field(
        default=None,
        alias="OpWorkQuantityUnit",
        description=(
            "Unit of the planned work as English unit code, e.g. 'HR' (hours) - use the unit of existing task lists. "
            "Required with `work`."
        ),
        max_length=3,
    )
    number_of_capacities: int | None = Field(
        default=None,
        alias="NumberOfCapacities",
        description="Number of people (capacities) needed for the operation, e.g. 2.",
        ge=0,
        le=255,
    )
    duration: SAPDecimal | None = Field(
        default=None,
        alias="OperationStandardDuration",
        description="Normal duration of the operation in `duration_unit`, e.g. 1.5.",
        ge=0,
    )
    duration_unit: SAPCode | None = Field(
        default=None,
        alias="OperationStandardDurationUnit",
        description=(
            "Unit of the duration as English unit code, e.g. 'HR' (hours) - use the unit of existing task lists. "
            "Required with `duration`."
        ),
        max_length=3,
    )
    materials: list[SAPTaskListOperationMaterialModel] = Field(
        default_factory=list,
        alias="_OpMaterial",
        description=(
            "Materials (components, e.g. spare parts) needed by the operation. They must be items of the plant "
            "maintenance BOM of the task list's assembly (or technical object)."
        ),
        exclude_if=is_empty,
    )

    @model_validator(mode="after")
    def check_units(self) -> Self:
        """Validate that work and duration have a unit (OData V4 rejects quantities without their unit)."""

        if self.work is not None and not self.work_unit:
            message = "Operation -> {} has `work` but no `work_unit`, e.g. 'H'".format(self.operation)
            raise ValueError(message)
        if self.duration is not None and not self.duration_unit:
            message = "Operation -> {} has a `duration` but no `duration_unit`, e.g. 'H'".format(self.operation)
            raise ValueError(message)

        return self

    # end method definition


class SAPTaskListModel(SAPODataCreateModel):
    """Data to create an SAP maintenance task list (API_MAINTENANCETASKLIST, OData V4).

    A task list describes the work (operations) of a maintenance task. It can be
    referenced by maintenance plan items and maintenance orders. There are three
    types: general task lists ('A', not bound to an object), equipment task lists
    ('E', need `equipment`) and functional location task lists ('T', need
    `functional_location`). The task list group is assigned by SAP unless it is given.

    A general task list with an assembly (a material, e.g. the construction type of
    equipment) applies to all equipment of this type. The materials of its operations
    (e.g. spare parts) are allocated via the plant maintenance BOM of the assembly -
    they can only be created together with the task list (not added later).

    See: https://api.sap.com/api/OP_API_MAINTENANCETASKLIST_0001/overview

    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "TaskListType": "A",
                    "TaskListDesc": "Quarterly pump inspection",
                    "MaintenancePlanningPlant": "1010",
                    "WorkCenter": "RES-0100",
                    "Plant": "1010",
                    "_Operation": [
                        {
                            "MaintenanceTaskListOperation": "0010",
                            "OperationText": "Check pump seal",
                            "OperationControlProfile": "PM01",
                            "OpPlannedWorkQuantity": 2,
                            "OpWorkQuantityUnit": "H",
                        }
                    ],
                }
            ]
        }
    )

    task_list_type: Literal["A", "E", "T"] = Field(
        alias="TaskListType",
        description="Task list type: 'A' general task list, 'E' equipment task list, 'T' functional location task list.",
    )
    task_list_group: SAPCode | None = Field(
        default=None,
        alias="TaskListGroup",
        description="Task list group for external number assignment. Omit to let SAP assign the group.",
        max_length=8,
    )
    description: str = Field(
        alias="TaskListDesc",
        description="Text of the task list, e.g. 'Quarterly pump inspection'.",
        min_length=1,
        max_length=40,
    )
    planning_plant: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant - the plant that plans the maintenance work, e.g. '1010'.",
        max_length=4,
    )
    equipment: SAPCode | None = Field(
        default=None,
        alias="Equipment",
        description="Equipment the task list is for, e.g. '210100001'. Required for equipment task lists (type 'E').",
        max_length=18,
    )
    assembly: SAPCode | None = Field(
        default=None,
        alias="Assembly",
        description=(
            "Assembly - the material (product) the work is done on, e.g. 'PUMP-100'. For general task lists (type 'A') "
            "it makes the task list reusable for all equipment of this construction type, and the materials of the "
            "operations come from its plant maintenance BOM."
        ),
        max_length=40,
    )
    functional_location: str | None = Field(
        default=None,
        alias="FunctionalLocationLabelName",
        description="Functional location label as shown in the SAP UI, e.g. 'C1-B01-1'. Required for functional location task lists (type 'T').",
        max_length=40,
    )
    work_center: SAPCode | None = Field(
        default=None,
        alias="WorkCenter",
        description="Main work center responsible for the task list, e.g. 'RES-0100'.",
        max_length=8,
    )
    plant: SAPCode | None = Field(
        default=None,
        alias="Plant",
        description="Plant of the work center, e.g. '1010'.",
        max_length=4,
    )
    planner_group: SAPCode | None = Field(
        default=None,
        alias="ResponsiblePlannerGroup",
        description="Maintenance planner group, e.g. '010' - system specific; copy from an existing task list if unsure.",
        max_length=3,
    )
    usage: SAPCode | None = Field(
        default=None,
        alias="TaskListUsage",
        description="Task list usage, e.g. '4' (plant maintenance) - system specific; copy from an existing task list if unsure.",
        max_length=3,
    )
    status: SAPCode | None = Field(
        default=None,
        alias="TaskListStatus",
        description="Task list status, e.g. '4' (released) - system specific; copy from an existing task list if unsure.",
        max_length=3,
    )
    strategy: SAPCode | None = Field(
        default=None,
        alias="MaintenanceStrategy",
        description="Maintenance strategy for task lists used in strategy plans, e.g. 'A' - system specific.",
        max_length=6,
    )
    system_condition: SAPCode | None = Field(
        default=None,
        alias="OperationSystemCondition",
        description="System condition during the work, e.g. '0' (out of operation), '1' (in operation) - system specific.",
        max_length=1,
    )
    validity_start_date: date | None = Field(
        default=None,
        alias="ValidityStartDate",
        description="Start of the validity of the task list, e.g. '2026-11-01'. SAP defaults it to today.",
    )
    operations: Annotated[list[SAPTaskListOperationModel], unique_numbers("operation")] = Field(
        default_factory=list,
        alias="_Operation",
        description="Operations of the task list (the work to do). Operation numbers must be unique.",
        exclude_if=is_empty,
    )

    @model_validator(mode="after")
    def check_technical_object(self) -> Self:
        """Validate that equipment and functional location task lists have their technical object."""

        if self.task_list_type == "E" and not self.equipment:
            message = "Equipment task lists (type 'E') need an equipment"
            raise ValueError(message)
        if self.task_list_type == "T" and not self.functional_location:
            message = "Functional location task lists (type 'T') need a functional location"
            raise ValueError(message)
        self.assign_operation_keys()

        # The materials are allocated via the BOM of the assembly - a general task list has no other object:
        if (
            self.task_list_type == "A"
            and not self.assembly
            and any(operation.materials for operation in self.operations)
        ):
            message = (
                "General task lists (type 'A') with materials in their operations need an assembly - the material "
                "whose plant maintenance BOM contains them"
            )
            raise ValueError(message)

        return self

    # end method definition

    def assign_operation_keys(self) -> None:
        """Set the task list type and operation number in operations with materials and their materials.

        SAP needs them to allocate the materials in the deep create of the task list.

        """

        for operation in self.operations:
            if not operation.materials:
                continue
            operation.task_list_type = self.task_list_type
            for material in operation.materials:
                material.task_list_type = self.task_list_type
                material.operation = operation.operation

    # end method definition


class SAPTaskListOperationMaterialResponseModel(SAPODataModel):
    """A material (component) of a task list operation as returned by SAP (API_MAINTENANCETASKLIST, OData V4)."""

    material: str | None = Field(default=None, alias="Material", description="Material (product) number.")
    material_name: str | None = Field(default=None, alias="MaterialName", description="Description of the material.")
    quantity: SAPDecimal | None = Field(
        default=None, alias="BillOfMaterialItemQuantity", description="Quantity needed for the operation."
    )
    unit: str | None = Field(default=None, alias="BillOfMaterialItemUnit", description="Unit of the quantity.")
    item_category: str | None = Field(
        default=None, alias="BillOfMaterialItemCategory", description="BOM item category, e.g. 'L' (stock item)."
    )
    bom_item: str | None = Field(
        default=None, alias="TaskListOpBOMItmInternalID", description="Internal ID (node number) of the BOM item."
    )


class SAPTaskListOperationResponseModel(SAPODataModel):
    """An operation of a maintenance task list as returned by SAP (API_MAINTENANCETASKLIST)."""

    task_list_type: str = Field(
        alias="TaskListType",
        description="Task list type: 'A' general, 'E' equipment, 'T' functional location task list.",
    )
    task_list_group: str = Field(alias="TaskListGroup", description="Task list group; see get_task_list().")
    task_list_group_counter: str = Field(
        alias="TaskListGroupCounter", description="Task list group counter - identifies the task list within the group."
    )
    sequence: str | None = Field(default=None, alias="TaskListSequence", description="Sequence of the operation.")
    operation_internal_id: str | None = Field(
        default=None, alias="TaskListOperationInternalId", description="Internal ID of the operation."
    )
    operation: str | None = Field(
        default=None, alias="MaintenanceTaskListOperation", description="Operation number, e.g. '0010'."
    )
    description: str | None = Field(default=None, alias="OperationText", description="Short text of the operation.")
    control_key: str | None = Field(
        default=None,
        alias="OperationControlProfile",
        description="Operation control key - how the operation is processed (e.g. internally or externally).",
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
    work: SAPDecimal | None = Field(
        default=None, alias="OpPlannedWorkQuantity", description="Planned work in `work_unit`."
    )
    work_unit: str | None = Field(
        default=None, alias="OpWorkQuantityUnit", description="Unit of the planned work (English unit code), e.g. 'HR'."
    )
    number_of_capacities: int | None = Field(
        default=None, alias="NumberOfCapacities", description="Number of people (capacities) needed."
    )
    duration: SAPDecimal | None = Field(
        default=None, alias="OperationStandardDuration", description="Normal duration in `duration_unit`."
    )
    duration_unit: str | None = Field(
        default=None,
        alias="OperationStandardDurationUnit",
        description="Unit of the duration (English unit code), e.g. 'HR'.",
    )
    activity_type: str | None = Field(
        default=None,
        alias="CostCtrActivityType",
        description="Activity type - the kind of work the work center's cost center charges for.",
    )
    validity_start_date: ODataDate = Field(
        default=None, alias="ValidityStartDate", description="Start of the validity period."
    )
    validity_end_date: ODataDate = Field(
        default=None, alias="ValidityEndDate", description="End of the validity period."
    )
    materials: list[SAPTaskListOperationMaterialResponseModel] | None = Field(
        default=None,
        alias="_OpMaterial",
        description="Materials (components) of the operation. None if not requested ($expand).",
    )


class SAPTaskListResponseModel(SAPODataModel):
    """A maintenance task list as returned by SAP (API_MAINTENANCETASKLIST, OData V4).

    A task list is identified by its type, group and group counter. With change
    numbers it can have several versions (TaskListVersionCounter).

    Attributes:
        operations (list[SAPTaskListOperationResponseModel] | None):
            None if the operations have not been requested ($expand), otherwise a (possibly empty) list.

    """

    task_list_type: str = Field(
        alias="TaskListType",
        description="Task list type: 'A' general, 'E' equipment, 'T' functional location task list.",
    )
    task_list_group: str = Field(alias="TaskListGroup", description="Task list group; see get_task_list().")
    task_list_group_counter: str = Field(
        alias="TaskListGroupCounter", description="Task list group counter - identifies the task list within the group."
    )
    version_counter: str | None = Field(
        default=None, alias="TaskListVersionCounter", description="Version of the task list (with change numbers)."
    )
    description: str | None = Field(default=None, alias="TaskListDesc", description="Text of the task list.")
    planning_plant: str | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant - the plant whose planner groups plan and schedule the maintenance work.",
    )
    plant: str | None = Field(default=None, alias="Plant", description="Plant of the work center.")
    work_center: str | None = Field(
        default=None,
        alias="WorkCenter",
        description="Main work center - responsible for executing the maintenance work; see get_work_center().",
    )
    planner_group: str | None = Field(
        default=None,
        alias="ResponsiblePlannerGroup",
        description="Planner group - the team that plans the maintenance work.",
    )
    usage: str | None = Field(default=None, alias="TaskListUsage", description="Task list usage.")
    status: str | None = Field(default=None, alias="TaskListStatus", description="Task list status, e.g. released.")
    status_description: str | None = Field(
        default=None, alias="TaskListStatusDesc", description="Text of the task list status."
    )
    strategy: str | None = Field(
        default=None, alias="MaintenanceStrategy", description="Maintenance strategy (for strategy plans)."
    )
    system_condition: str | None = Field(
        default=None,
        alias="OperationSystemCondition",
        description="System condition during the work, e.g. '0' (out of operation), '1' (in operation).",
    )
    technical_object: str | None = Field(
        default=None,
        alias="TechnicalObject",
        description="Technical object (equipment or functional location) of the task list.",
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
    assembly: str | None = Field(
        default=None, alias="Assembly", description="Assembly (material) of the technical object the work is done on."
    )
    validity_start_date: ODataDate = Field(
        default=None, alias="ValidityStartDate", description="Start of the validity period."
    )
    validity_end_date: ODataDate = Field(
        default=None, alias="ValidityEndDate", description="End of the validity period."
    )
    is_marked_for_deletion: bool | None = Field(
        default=None, alias="IsMarkedForDeletion", description="True if the task list is marked for deletion."
    )
    creation_date: ODataDate = Field(
        default=None, alias="CreationDate", description="Date the record was created in SAP."
    )
    created_by_user: str | None = Field(
        default=None, alias="CreatedByUser", description="SAP user ID of the user who created the record."
    )
    last_change_date: ODataDate = Field(
        default=None, alias="LastChangeDate", description="Date of the last change in SAP."
    )
    last_changed_by_user: str | None = Field(
        default=None, alias="LastChangedByUser", description="SAP user ID of the user who last changed the record."
    )
    operations: list[SAPTaskListOperationResponseModel] | None = Field(
        default=None,
        alias="_Operation",
        description="Operations. None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPTaskListQueryModel(SAPODataQueryModel):
    """Search criteria for SAP maintenance task lists (API_MAINTENANCETASKLIST, OData V4)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        # Latest version first for each task list (see get_task_list()):
        "task_list": "TaskListType {direction},TaskListGroup {direction},TaskListGroupCounter {direction},"
        "TaskListVersionCounter desc",
        "last_change": "LastChangeDate {direction}",
    }
    EXPAND: ClassVar[str] = "_Operation($expand=_OpMaterial)"
    sort_by: Literal["task_list", "last_change"] = Field(default="task_list", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    task_list_types: Annotated[list[SAPCode] | None, ODataCondition("TaskListType")] = Field(
        default=None, description="Task list types: 'A' general, 'E' equipment, 'T' functional location task list."
    )
    task_list_groups: Annotated[list[SAPCode] | None, ODataCondition("TaskListGroup")] = Field(
        default=None, description="Task list groups."
    )
    task_list_group_counters: Annotated[list[SAPCode] | None, ODataCondition("TaskListGroupCounter")] = Field(
        default=None, description="Task list group counters, e.g. ['1']."
    )
    description_contains: Annotated[str | None, ODataCondition("TaskListDesc", operator="contains")] = Field(
        default=None, description="Text contained in the task list description (case-sensitive)."
    )
    planning_plant: Annotated[SAPCode | None, ODataCondition("MaintenancePlanningPlant")] = Field(
        default=None, description="Plant that plans the maintenance work, e.g. '1010'."
    )
    equipment: Annotated[SAPCode | None, ODataCondition("Equipment")] = Field(
        default=None, description="Only task lists for this equipment."
    )
    functional_location: Annotated[str | None, ODataCondition("FunctionalLocationLabelName")] = Field(
        default=None, description="Only task lists for this functional location (label as shown in the UI)."
    )
    work_center: Annotated[SAPCode | None, ODataCondition("WorkCenter")] = Field(
        default=None, description="Main work center of the task lists."
    )
    strategies: Annotated[list[SAPCode] | None, ODataCondition("MaintenanceStrategy")] = Field(
        default=None, description="Maintenance strategies. System specific."
    )
    statuses: Annotated[list[SAPCode] | None, ODataCondition("TaskListStatus")] = Field(
        default=None, description="Task list statuses. System specific."
    )
    is_marked_for_deletion: Annotated[bool | None, ODataCondition("IsMarkedForDeletion")] = Field(
        default=None, description="False = only task lists that are not marked for deletion."
    )
    valid_on: Annotated[date | None, ODataCondition(("ValidityStartDate", "ValidityEndDate"), operator="valid_on")] = (
        Field(default=None, description="Only task lists valid on this date (e.g. today for the current ones).")
    )
    expand_items: bool = Field(default=False, description="Also return the operations of each task list.")


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
                    "BaseUnit": "PC",
                    "PlndOrderPlannedStartDate": "2026-11-09",
                    "PlndOrderPlannedEndDate": "2026-11-16",
                }
            ]
        }
    )

    order_type: SAPCode = Field(
        alias="PlannedOrderType",
        description="Planned order type, e.g. 'LA' (stock order), 'KD' (customer order) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="MRP area. Defaults to the MRP plant (plant MRP area).",
        max_length=10,
    )
    # API_PLANNEDORDER only creates planned orders for in-house production - SAP rejects other
    # values and an empty value ("MaterialProcurementCategory: Only E supported"):
    procurement_category: Literal["E"] = Field(
        default="E",
        alias="MaterialProcurementCategory",
        description="Procurement category - always 'E' (in-house production), the only value the API supports.",
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
    # OData V4 requires the unit together with the quantity (/IWBEP/CM_V4S_RUN/049):
    unit: SAPCode = Field(
        alias="BaseUnit",
        description="Base unit of the material as English unit code, e.g. 'PC' (piece) - internal codes like 'ST' are rejected.",
        min_length=1,
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
        """Validate the dates and default the MRP area to the MRP plant.

        Without an explicit MRP area SAP rejects the procurement category ("MRP area E has not
        been defined").

        """

        self.mrp_area = self.mrp_area or self.mrp_plant
        if not self.start_date and not self.end_date:
            message = "Give an `end_date` and/or a `start_date` - SAP schedules the planned order from them"
            raise ValueError(message)
        if self.start_date and self.end_date and self.end_date < self.start_date:
            message = "Planned end date -> {} is before planned start date -> {}".format(
                self.end_date,
                self.start_date,
            )
            raise ValueError(message)

        return self

    # end method definition


class SAPPlannedOrderComponentModel(SAPODataCreateModel):
    """The changeable fields of a component of an SAP planned order (API_PLANNEDORDER, PlannedOrderComponent).

    Only used to validate component changes (see SAP.update_planned_order()) - components are
    created by SAP from the bill of material.
    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        # Verified in S/4HANA: the PATCH succeeds, but the quantity stays unchanged (also with a fixed
        # quantity or a fixed BOM of the planned order):
        "RequiredQuantity": "SAP ignores changes of the required quantity of a component - it follows the "
        "planned order quantity and the bill of material; change the planned order quantity instead",
    }

    requirement_date: date | None = Field(
        default=None,
        alias="MatlCompRequirementDate",
        description="Requirement date of the component, e.g. '2026-11-02'.",
    )
    storage_location: SAPCode | None = Field(
        default=None,
        alias="StorageLocation",
        description="Storage location the component is taken from, e.g. '0001'.",
        max_length=4,
    )
    quantity_is_fixed: bool | None = Field(
        default=None,
        alias="QuantityIsFixed",
        description="Whether the quantity is fixed (independent of the order quantity).",
    )


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
        default=None, alias="BaseUnit", description="Base unit of the material (English unit code, e.g. 'PC')."
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
        description="Production order type, e.g. 'PP01' (standard production order) - system specific; look up the valid values (e.g. in similar documents) if unknown.",
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
        description="Production unit as English unit code, e.g. 'PC'. Defaults to the base unit of the material.",
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
        description="Basic scheduling type: '1' (forwards from `planned_start_date`) or '2' (backwards from `planned_end_date`). Omit it to derive it from the given date.",
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
        """Validate the planned dates and derive the scheduling type.

        SAP schedules forwards from the start date or backwards from the end date. Without a
        scheduling type it uses the default of the order type (e.g. backwards for PP01), which
        fails if only the start date is given ("CO/028 Backward scheduling (enter finish date)").

        """

        if not self.planned_start_date and not self.planned_end_date:
            message = "Give a `planned_end_date` (backward scheduling) or a `planned_start_date` (forward scheduling)"
            raise ValueError(message)
        if not self.scheduling_type:
            self.scheduling_type = "2" if self.planned_end_date else "1"
        if self.scheduling_type == "1" and not self.planned_start_date:
            message = "Forward scheduling (`scheduling_type` '1') needs a `planned_start_date`"
            raise ValueError(message)
        if self.scheduling_type == "2" and not self.planned_end_date:
            message = "Backward scheduling (`scheduling_type` '2') needs a `planned_end_date`"
            raise ValueError(message)
        if self.planned_start_date and self.planned_end_date and self.planned_end_date < self.planned_start_date:
            message = "Planned end date -> {} is before planned start date -> {}".format(
                self.planned_end_date,
                self.planned_start_date,
            )
            raise ValueError(message)

        return self

    # end method definition


class SAPProductionOrderOperationModel(SAPODataCreateModel):
    """The changeable fields of an operation of an SAP production order (API_PRODUCTION_ORDER_2_SRV).

    Only used to validate operation changes (see SAP.update_production_order()) - operations are
    created by SAP from the routing.
    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        # Verified in S/4HANA (also for orders that are not released): SAP rejects these changes,
        # although $metadata declares the properties as updatable:
        "OpPlannedTotalQuantity": "the operation quantity follows the order quantity - change the order quantity "
        "instead",
        "ErlstSchedldExecDurnInWorkdays": "SAP schedules the operations - change the order dates instead",
        "OpErlstSchedldExecStrtDte": "SAP schedules the operations - change the order dates instead",
        "OpErlstSchedldExecStrtTme": "SAP schedules the operations - change the order dates instead",
        "OpErlstSchedldExecEndDte": "SAP schedules the operations - change the order dates instead",
        "OpErlstSchedldExecEndTme": "SAP schedules the operations - change the order dates instead",
        "OpErlstSchedldProcgStrtDte": "SAP schedules the operations - change the order dates instead",
        "OpErlstSchedldProcgStrtTme": "SAP schedules the operations - change the order dates instead",
        "OpErlstSchedldTrdwnStrtDte": "SAP schedules the operations - change the order dates instead",
        "OpErlstSchedldTrdwnStrtTme": "SAP schedules the operations - change the order dates instead",
    }

    description: str | None = Field(
        default=None,
        alias="MfgOrderOperationText",
        description="Short text of the operation (max. 40 characters).",
        max_length=40,
    )
    work_center: SAPCode | None = Field(
        default=None,
        alias="WorkCenter",
        description="Work center of the operation, e.g. '1320'.",
        max_length=8,
    )
    standard_value_1: SAPDecimal | None = Field(
        default=None,
        alias="WorkCenterStandardWorkQty1",
        description="First standard value of the operation (e.g. the setup time - see the work center). Only for "
        "operations with a work center.",
        ge=0,
        max_digits=9,
        decimal_places=3,
    )
    standard_value_2: SAPDecimal | None = Field(
        default=None,
        alias="WorkCenterStandardWorkQty2",
        description="Second standard value of the operation (e.g. the machine time - see the work center).",
        ge=0,
        max_digits=9,
        decimal_places=3,
    )
    standard_value_3: SAPDecimal | None = Field(
        default=None,
        alias="WorkCenterStandardWorkQty3",
        description="Third standard value of the operation (e.g. the labor time - see the work center).",
        ge=0,
        max_digits=9,
        decimal_places=3,
    )


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
        default=None,
        alias="OperationUnit",
        description="Unit of the operation quantities (English unit code, e.g. 'PC').",
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
        default=None, alias="ProductionUnit", description="Production unit (English unit code, e.g. 'PC')."
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


class SAPProductDescriptionModel(SAPODataCreateModel):
    """A (language dependent) description of a new product."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Product": "the product number is part of the key",
        "Language": "the language is part of the key",
    }

    # Filled with the number of the product (see SAPProductModel.check_product_ids()) - with an external
    # number SAP rejects children without it ("Cannot process multiple products in a single change set"):
    product_id: SkipJsonSchema[SAPCode | None] = Field(default=None, alias="Product", max_length=40)
    language: SAPCode = Field(
        alias="Language",
        description="Language key of the description, e.g. 'EN'.",
        min_length=1,
        max_length=2,
    )
    description: str = Field(
        alias="ProductDescription",
        description="Description of the product in this language, e.g. 'Pump seal 50 mm'.",
        min_length=1,
        max_length=40,
    )


class SAPProductStorageLocationModel(SAPODataCreateModel):
    """The storage location data of a product in a plant (extends the product to a storage location)."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Product": "the product number is part of the key",
        "Plant": "the plant is part of the key",
        "StorageLocation": "the storage location is part of the key",
    }

    # Filled with the product number and plant (see SAPProductPlantModel.assign_product_id()):
    product_id: SkipJsonSchema[SAPCode | None] = Field(default=None, alias="Product", max_length=40)
    plant: SkipJsonSchema[SAPCode | None] = Field(default=None, alias="Plant", max_length=4)
    storage_location: SAPCode = Field(
        alias="StorageLocation",
        description="Storage location in the plant, e.g. '0001' - needed to keep the product in stock there.",
        min_length=1,
        max_length=4,
    )
    storage_bin: SAPCode | None = Field(
        default=None,
        alias="WarehouseStorageBin",
        description="Storage bin in the storage location, e.g. 'A-01-02'.",
        max_length=10,
    )


class SAPProductPlantModel(SAPODataCreateModel):
    """The plant specific data of a product (extends the product to a plant) - with its storage locations."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Product": "the product number is part of the key",
        "Plant": "the plant is part of the key",
    }

    # Filled with the number of the product (see SAPProductModel.check_product_ids()) - with an external
    # number SAP rejects children without it ("Cannot process multiple products in a single change set"):
    product_id: SkipJsonSchema[SAPCode | None] = Field(default=None, alias="Product", max_length=40)
    plant: SAPCode = Field(
        alias="Plant",
        description="Plant to extend the product to, e.g. '1010'.",
        min_length=1,
        max_length=4,
    )
    mrp_type: SAPCode | None = Field(
        default=None,
        alias="MRPType",
        description="MRP type, e.g. 'PD' (MRP), 'ND' (no planning) - system specific.",
        max_length=2,
    )
    mrp_controller: SAPCode | None = Field(
        default=None,
        alias="MRPResponsible",
        description="MRP controller responsible for the product in the plant, e.g. '001' - system specific.",
        max_length=3,
    )
    procurement_type: SAPCode | None = Field(
        default=None,
        alias="ProcurementType",
        description="Procurement type: 'E' in-house production, 'F' external procurement, 'X' both.",
        max_length=1,
    )
    purchasing_group: SAPCode | None = Field(
        default=None,
        alias="PurchasingGroup",
        description="Purchasing group responsible for the product in the plant, e.g. '001' - system specific.",
        max_length=3,
    )
    profit_center: SAPCode | None = Field(
        default=None,
        alias="ProfitCenter",
        description="Profit center the values are reported on.",
        max_length=10,
    )
    availability_check_type: SAPCode | None = Field(
        default=None,
        alias="AvailabilityCheckType",
        description="Checking group for the availability check, e.g. '02' - system specific.",
        max_length=2,
    )
    is_batch_managed: bool | None = Field(
        default=None,
        alias="IsBatchManagementRequired",
        description=(
            "True if the product is managed in batches in this plant. SAP needs it on the product as well "
            "(is_batch_managed of the product) and allows to change it only as long as there is no stock."
        ),
    )
    storage_locations: Annotated[list[SAPProductStorageLocationModel], unique_numbers("storage_location")] = Field(
        default_factory=list,
        alias="to_StorageLocation",
        description="Storage locations to extend the product to in this plant, e.g. [{'StorageLocation': '0001'}].",
        exclude_if=is_empty,
    )

    @model_validator(mode="after")
    def check_storage_locations(self) -> Self:
        """Fill in the plant for the storage locations."""

        self.assign_product_id(self.product_id)

        return self

    # end method definition

    def assign_product_id(self, product_id: str | None) -> None:
        """Set the product number of the plant data and its storage locations (needed with an external number).

        Args:
            product_id (str | None):
                The product number.

        """

        self.product_id = self.product_id or product_id
        for storage_location in self.storage_locations:
            storage_location.product_id = storage_location.product_id or self.product_id
            storage_location.plant = storage_location.plant or self.plant

    # end method definition


class SAPProductValuationModel(SAPODataCreateModel):
    """The valuation data of a product in a valuation area (usually a plant) - needed for stock postings."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Product": "the product number is part of the key",
        "ValuationArea": "the valuation area is part of the key",
        "ValuationType": "the valuation type is part of the key",
    }

    # Filled with the number of the product (see SAPProductModel.check_product_ids()):
    product_id: SkipJsonSchema[SAPCode | None] = Field(default=None, alias="Product", max_length=40)
    valuation_area: SAPCode = Field(
        alias="ValuationArea",
        description="Valuation area - usually the plant, e.g. '3000'.",
        min_length=1,
        max_length=4,
    )
    # Empty for products without split valuation (the standard) - SAP needs the key property:
    valuation_type: SkipJsonSchema[str] = Field(default="", alias="ValuationType", max_length=10)
    valuation_class: SAPCode = Field(
        alias="ValuationClass",
        description=(
            "Valuation class (determines the G/L accounts), e.g. '3000' - system specific and must fit the "
            "product type; copy from a similar product if unsure."
        ),
        min_length=1,
        max_length=4,
    )
    price_control: Literal["S", "V"] = Field(
        default="V",
        alias="InventoryValuationProcedure",
        description="Price control: 'V' (moving average price) or 'S' (standard price).",
    )
    moving_average_price: SAPDecimal | None = Field(
        default=None,
        alias="MovingAveragePrice",
        description="Moving average price per price unit (price control 'V'), e.g. 120.50.",
        ge=0,
    )
    standard_price: SAPDecimal | None = Field(
        default=None,
        alias="StandardPrice",
        description="Standard price per price unit (price control 'S').",
        ge=0,
    )
    price_unit: SAPDecimal | None = Field(
        default=None,
        alias="PriceUnitQty",
        description="Number of units the price refers to, e.g. 1. Defaults to 1.",
        gt=0,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="Currency",
        description="Currency of the prices (ISO code), e.g. 'USD' - the currency of the company code.",
    )

    @model_validator(mode="after")
    def check_price(self) -> Self:
        """Check that the price of the price control is given."""

        if self.price_control == "S" and self.standard_price is None:
            message = "Price control 'S' needs a standard price (StandardPrice)"
            raise ValueError(message)
        if self.price_control == "V" and self.moving_average_price is None:
            message = "Price control 'V' needs a moving average price (MovingAveragePrice)"
            raise ValueError(message)

        return self

    # end method definition


class SAPProductModel(SAPODataCreateModel):
    """Data to create an SAP product / material (API_PRODUCT_SRV, OData V2).

    The product number is assigned by SAP unless it is given (external number
    assignment - depends on the customizing of the product type). Descriptions,
    plant data (with storage locations) and valuation data are created together with
    the product (deep insert) - existing products are extended with
    SAP.create_product_plant(), create_product_storage_location() and
    create_product_valuation(). Additional OData properties of the product that are
    not modelled here can be passed with their OData name (e.g. "ProductHierarchy").

    See: https://api.sap.com/api/API_PRODUCT_SRV/overview

    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Product": "the product number is the key of the product",
        "ProductType": "SAP does not allow to change the product type with the API",
        "to_Description": "use update_product_description()",
        "to_Plant": "use update_product_plant() / create_product_plant()",
        "to_Valuation": "use create_product_valuation()",
    }

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "Product": "PUMP-SEAL-50",
                    "ProductType": "ERSA",
                    "IndustrySector": "M",
                    "BaseUnit": "ST",
                    "ProductGroup": "L001",
                    "to_Description": [{"Language": "EN", "ProductDescription": "Pump seal 50 mm"}],
                    "to_Plant": [{"Plant": "1010", "MRPType": "ND"}],
                }
            ]
        }
    )

    product_id: SAPCode | None = Field(
        default=None,
        alias="Product",
        description="Product (material) number for external number assignment, e.g. 'PUMP-SEAL-50'. Omit to let SAP assign the number.",
        max_length=40,
    )
    product_type: SAPCode = Field(
        alias="ProductType",
        description="Product type, e.g. 'FERT' (finished product), 'ROH' (raw material), 'HAWA' (trading good), 'ERSA' (spare part).",
        min_length=1,
        max_length=4,
    )
    base_unit: SAPCode = Field(
        alias="BaseUnit",
        description="Base unit of measure (English unit code), e.g. 'PC' (piece), 'KG'.",
        min_length=1,
        max_length=3,
    )
    industry_sector: SAPCode | None = Field(
        default=None,
        alias="IndustrySector",
        description="Industry sector, e.g. 'M' (mechanical engineering) - usually required; system specific.",
        max_length=1,
    )
    product_group: SAPCode | None = Field(
        default=None,
        alias="ProductGroup",
        description="Product (material) group, e.g. 'L001' - system specific; copy from an existing product if unsure.",
        max_length=9,
    )
    division: SAPCode | None = Field(
        default=None,
        alias="Division",
        description="Division (product line), e.g. '00'.",
        max_length=2,
    )
    gross_weight: SAPDecimal | None = Field(
        default=None,
        alias="GrossWeight",
        description="Gross weight in `weight_unit`.",
        ge=0,
    )
    net_weight: SAPDecimal | None = Field(
        default=None,
        alias="NetWeight",
        description="Net weight in `weight_unit`.",
        ge=0,
    )
    weight_unit: SAPCode | None = Field(
        default=None,
        alias="WeightUnit",
        description="Unit of the weights (English unit code), e.g. 'KG'.",
        max_length=3,
    )
    old_id: str | None = Field(
        default=None,
        alias="ProductOldID",
        description="Old (legacy) product number.",
        max_length=40,
    )
    manufacturer_number: SAPCode | None = Field(
        default=None,
        alias="ManufacturerNumber",
        description=(
            "Business partner number of the manufacturer (not its name) - the manufacturer has to exist as a "
            "business partner in SAP; see get_business_partners()."
        ),
        max_length=10,
    )
    manufacturer_part_number: str | None = Field(
        default=None,
        alias="ProductManufacturerNumber",
        description="Part number of the manufacturer (order number in the manufacturer's catalog). SAP stores it in upper case.",
        max_length=40,
    )
    is_batch_managed: bool | None = Field(
        default=None,
        alias="IsBatchManagementRequired",
        description=(
            "True if the product is managed in batches (e.g. to trace defective deliveries). SAP needs it on the "
            "product and in each plant - it is passed on to the plants of the product that don't set it. Can "
            "only be changed as long as there is no stock of the product."
        ),
    )
    descriptions: list[SAPProductDescriptionModel] = Field(
        default_factory=list,
        alias="to_Description",
        description="Descriptions per language - give at least one.",
        exclude_if=is_empty,
    )
    plants: list[SAPProductPlantModel] = Field(
        default_factory=list,
        alias="to_Plant",
        description="Plants (with their storage locations) to extend the product to.",
        exclude_if=is_empty,
    )
    valuations: list[SAPProductValuationModel] = Field(
        default_factory=list,
        alias="to_Valuation",
        description="Valuation data per valuation area (plant) - needed to post stock of the product.",
        exclude_if=is_empty,
    )

    @model_validator(mode="after")
    def check_product_ids(self) -> Self:
        """Fill in the product number for the descriptions, plants and valuations (needed with an external number)."""

        for child in [*self.descriptions, *self.plants, *self.valuations]:
            child.product_id = child.product_id or self.product_id
            if child.product_id != self.product_id:
                message = "The descriptions, plants and valuations must belong to product -> '{}', got -> '{}'".format(
                    self.product_id, child.product_id
                )
                raise ValueError(message)
        for plant in self.plants:
            plant.assign_product_id(self.product_id)

        return self

    # end method definition

    @model_validator(mode="after")
    def check_batch_management(self) -> Self:
        """Set batch management on the product and its plants - SAP needs it on both levels."""

        if self.is_batch_managed is None and any(plant.is_batch_managed for plant in self.plants):
            self.is_batch_managed = True
        for plant in self.plants:
            if plant.is_batch_managed is None:
                plant.is_batch_managed = self.is_batch_managed

        return self

    # end method definition


class SAPProductDescriptionResponseModel(SAPODataModel):
    """A (language dependent) description of a product as returned by SAP (API_PRODUCT_SRV)."""

    product_id: str = Field(alias="Product", description="Product (material) number.")
    language: str = Field(alias="Language", description="Language key of the description, e.g. 'EN'.")
    description: str | None = Field(
        default=None, alias="ProductDescription", description="Description of the product in this language."
    )


class SAPProductStorageLocationResponseModel(SAPODataModel):
    """The storage location data of a product as returned by SAP (API_PRODUCT_SRV)."""

    product_id: str = Field(alias="Product", description="Product (material) number.")
    plant: str = Field(alias="Plant", description="Plant.")
    storage_location: str = Field(alias="StorageLocation", description="Storage location; see get_storage_locations().")
    storage_bin: str | None = Field(default=None, alias="WarehouseStorageBin", description="Storage bin.")
    is_marked_for_deletion: bool | None = Field(
        default=None, alias="IsMarkedForDeletion", description="True if marked for deletion in the storage location."
    )


class SAPProductValuationResponseModel(SAPODataModel):
    """The valuation data of a product in a valuation area as returned by SAP (API_PRODUCT_SRV)."""

    product_id: str = Field(alias="Product", description="Product (material) number.")
    valuation_area: str = Field(alias="ValuationArea", description="Valuation area - usually the plant.")
    valuation_type: str | None = Field(
        default=None, alias="ValuationType", description="Valuation type (empty without split valuation)."
    )
    valuation_class: str | None = Field(
        default=None, alias="ValuationClass", description="Valuation class (determines the G/L accounts)."
    )
    price_control: str | None = Field(
        default=None,
        alias="InventoryValuationProcedure",
        description="Price control: 'V' (moving average price) or 'S' (standard price).",
    )
    moving_average_price: SAPDecimal | None = Field(
        default=None, alias="MovingAveragePrice", description="Moving average price per price unit."
    )
    standard_price: SAPDecimal | None = Field(
        default=None, alias="StandardPrice", description="Standard price per price unit."
    )
    price_unit: SAPDecimal | None = Field(
        default=None, alias="PriceUnitQty", description="Number of units the price refers to."
    )
    currency: str | None = Field(default=None, alias="Currency", description="Currency of the prices.")
    is_marked_for_deletion: bool | None = Field(
        default=None, alias="IsMarkedForDeletion", description="True if the valuation data is marked for deletion."
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
        default=None, alias="BaseUnit", description="Base unit of the product (English unit code, e.g. 'PC')."
    )
    is_batch_managed: bool | None = Field(
        default=None,
        alias="IsBatchManagementRequired",
        description=(
            "True if the product is managed in batches in this plant. SAP needs it on the product as well "
            "(is_batch_managed of the product) and allows to change it only as long as there is no stock."
        ),
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
    storage_locations: Annotated[
        list[SAPProductStorageLocationResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_StorageLocation",
        description="Storage locations the product is extended to. None if not requested ($expand).",
    )


class SAPProductResponseModel(SAPODataModel):
    """A product (material) as returned by SAP (API_PRODUCT_SRV, OData V2).

    Attributes:
        descriptions / plants (with their storage locations) / valuations:
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
        default=None, alias="BaseUnit", description="Base unit of measure (English unit code), e.g. 'PC'."
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
    manufacturer_number: str | None = Field(
        default=None,
        alias="ManufacturerNumber",
        description="Business partner number of the manufacturer; see get_business_partner().",
    )
    manufacturer_part_number: str | None = Field(
        default=None, alias="ProductManufacturerNumber", description="Part number of the manufacturer."
    )
    is_batch_managed: bool | None = Field(
        default=None,
        alias="IsBatchManagementRequired",
        description="True if the product is managed in batches (see also the plant data).",
    )
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
    valuations: Annotated[
        list[SAPProductValuationResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_Valuation",
        description="Valuation data per valuation area (plant). None if not requested ($expand).",
    )


class SAPProductQueryModel(SAPODataQueryModel):
    """Search criteria for SAP products / materials (API_PRODUCT_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"product": "Product {direction}"}
    EXPAND: ClassVar[str] = "to_Description,to_Plant"
    TEXT_SEARCH: ClassVar[ODataTextSearch | None] = ODataTextSearch(
        field="description_contains",
        entity_set="A_ProductDescription",
        properties=("ProductDescription",),
        key="Product",
        ids_field="product_ids",
    )
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
    is_batch_managed: Annotated[bool | None, ODataCondition("IsBatchManagementRequired")] = Field(
        default=None, description="True = only products managed in batches, False = only products without batches."
    )
    is_marked_for_deletion: Annotated[bool | None, ODataCondition("IsMarkedForDeletion")] = Field(
        default=None, description="True = only products marked for deletion, False = only active products."
    )
    description_contains: str | None = Field(
        default=None, description="Text contained in the product description (any language), e.g. 'seal kit'."
    )
    expand_items: bool = Field(
        default=False, description="Also return the descriptions and plant data of each product."
    )


class SAPMaterialBOMItemModel(SAPODataCreateModel):
    """An item (component) of a new material BOM."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "BillOfMaterialItemNumber": "the item number identifies the item",
        "BillOfMaterialComponent": "SAP does not allow to change the component - delete and create the item",
        # Verified in S/4HANA: SAP accepts the change, but keeps the old value:
        "FixedQuantity": "SAP ignores this field - use BOMItemHasFixedQuantity for a fixed quantity",
    }

    item_number: Numc4 | None = Field(
        default=None,
        alias="BillOfMaterialItemNumber",
        description="Item number (4 digits, padded), e.g. 10 -> '0010'. Omit it to number the items 0010, 0020, ...",
    )
    item_category: SAPCode = Field(
        default="L",
        alias="BillOfMaterialItemCategory",
        description="Item category, e.g. 'L' (stock item), 'N' (non-stock item), 'T' (text item).",
        min_length=1,
        max_length=1,
    )
    component: SAPCode = Field(
        alias="BillOfMaterialComponent",
        description="Material (product) number of the component, e.g. 'SEAL-KIT-50'; see get_products().",
        min_length=1,
        max_length=40,
    )
    quantity: SAPDecimal = Field(
        alias="BillOfMaterialItemQuantity",
        description="Quantity of the component per base quantity of the BOM, e.g. 1.",
        gt=0,
    )
    unit: SAPCode | None = Field(
        default=None,
        alias="BillOfMaterialItemUnit",
        description="Unit of the quantity (English unit code), e.g. 'PC'. Defaults to the base unit of the component.",
        max_length=3,
    )


class SAPMaterialBOMModel(SAPODataCreateModel):
    """Data to create a material BOM (bill of material) of a product in a plant (API_BILL_OF_MATERIAL_SRV, V2).

    The BOM lists the components of the product. With the usage '4' (plant maintenance)
    it is the spare parts list of all equipment with this product as construction type
    (see SAPEquipmentModel.construction_material). The items are created together with
    the BOM (deep insert).

    See: https://api.sap.com/api/API_BILL_OF_MATERIAL_SRV_0002/overview

    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Material": "the material is part of the key of the BOM",
        "Plant": "the plant is part of the key of the BOM",
        "BillOfMaterialVariantUsage": "the BOM usage is part of the BOM - create a BOM with the other usage",
        "to_BillOfMaterialItem": "the items are only created together with the BOM",
    }

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "Material": "PUMP-100",
                    "Plant": "3000",
                    "BillOfMaterialVariantUsage": "4",
                    "BOMHeaderQuantityInBaseUnit": 1,
                    "BOMHeaderText": "Spare parts pump PUMP-100",
                    "to_BillOfMaterialItem": [
                        {"BillOfMaterialComponent": "SEAL-KIT-50", "BillOfMaterialItemQuantity": 1}
                    ],
                }
            ]
        }
    )

    material: SAPCode = Field(
        alias="Material",
        description="Material (product) number the BOM belongs to, e.g. 'PUMP-100'.",
        min_length=1,
        max_length=40,
    )
    plant: SAPCode = Field(
        alias="Plant",
        description="Plant of the BOM, e.g. '3000'. The material and its components must exist in this plant.",
        min_length=1,
        max_length=4,
    )
    usage: SAPCode = Field(
        alias="BillOfMaterialVariantUsage",
        description="BOM usage, e.g. '1' (production), '4' (plant maintenance - spare parts), '5' (sales).",
        min_length=1,
        max_length=1,
    )
    alternative: SAPCode | None = Field(
        default=None,
        alias="BillOfMaterialVariant",
        description="Alternative BOM, e.g. '1'. Omit it for the first BOM of the material and usage.",
        max_length=2,
    )
    base_quantity: SAPDecimal | None = Field(
        default=None,
        alias="BOMHeaderQuantityInBaseUnit",
        description="Base quantity the item quantities refer to, e.g. 1. Defaults to 1.",
        gt=0,
    )
    valid_from: ODataV2Date = Field(
        default=None,
        alias="HeaderValidityStartDate",
        description="Start of the validity of the BOM, e.g. '2025-04-01'. SAP defaults it to today.",
    )
    text: str | None = Field(
        default=None,
        alias="BOMHeaderText",
        description="Text of the BOM, e.g. 'Spare parts pump PUMP-100'.",
        max_length=40,
    )
    items: Annotated[list[SAPMaterialBOMItemModel], unique_numbers("item_number")] = Field(
        alias="to_BillOfMaterialItem",
        description="Items (components) - give at least one.",
        min_length=1,
    )

    @model_validator(mode="before")
    @classmethod
    def number_items(cls, data: object) -> object:
        """Assign the item numbers 0010, 0020, ... to the items without one (after the highest given number)."""

        if not isinstance(data, dict):
            return data

        key = "to_BillOfMaterialItem" if "to_BillOfMaterialItem" in data else "items"
        items = data.get(key)
        if not isinstance(items, list):
            return data

        def given_number(item: object) -> int | None:
            if isinstance(item, dict):
                number = item.get("BillOfMaterialItemNumber", item.get("item_number"))
            else:
                number = getattr(item, "item_number", None)
            return int(number) if number not in (None, "") and str(number).strip().isdigit() else None

        next_number = max((number for item in items if (number := given_number(item)) is not None), default=0)
        numbered = []
        for item in items:
            if isinstance(item, dict) and given_number(item) is None:
                next_number += 10
                item = {**item, "BillOfMaterialItemNumber": str(next_number)}
            numbered.append(item)

        return {**data, key: numbered}

    # end method definition


class SAPMaterialBOMItemResponseModel(SAPODataModel):
    """An item (component) of a material BOM as returned by SAP (API_BILL_OF_MATERIAL_SRV)."""

    item_number: str | None = Field(default=None, alias="BillOfMaterialItemNumber", description="Item number.")
    item_node: str | None = Field(
        default=None,
        alias="BillOfMaterialItemNodeNumber",
        description="Internal ID (node number) of the item - referenced by task list operation materials.",
    )
    item_category: str | None = Field(
        default=None, alias="BillOfMaterialItemCategory", description="Item category, e.g. 'L' (stock item)."
    )
    component: str | None = Field(
        default=None, alias="BillOfMaterialComponent", description="Material (product) number of the component."
    )
    component_description: str | None = Field(
        default=None, alias="ComponentDescription", description="Description of the component."
    )
    quantity: SAPDecimal | None = Field(
        default=None, alias="BillOfMaterialItemQuantity", description="Quantity per base quantity of the BOM."
    )
    unit: str | None = Field(default=None, alias="BillOfMaterialItemUnit", description="Unit of the quantity.")
    valid_from: ODataDate = Field(default=None, alias="ValidityStartDate", description="Start of the validity.")


class SAPMaterialBOMResponseModel(SAPODataModel):
    """A material BOM as returned by SAP (API_BILL_OF_MATERIAL_SRV, OData V2).

    Attributes:
        items (list[SAPMaterialBOMItemResponseModel] | None):
            None if the items have not been requested ($expand), otherwise a (possibly empty) list.

    """

    bom_id: str | None = Field(default=None, alias="BillOfMaterial", description="Internal BOM number.")
    material: str | None = Field(default=None, alias="Material", description="Material (product) of the BOM.")
    plant: str | None = Field(default=None, alias="Plant", description="Plant of the BOM.")
    usage: str | None = Field(
        default=None,
        alias="BillOfMaterialVariantUsage",
        description="BOM usage, e.g. '1' (production), '4' (plant maintenance).",
    )
    alternative: str | None = Field(default=None, alias="BillOfMaterialVariant", description="Alternative BOM.")
    base_quantity: SAPDecimal | None = Field(
        default=None, alias="BOMHeaderQuantityInBaseUnit", description="Base quantity the item quantities refer to."
    )
    base_unit: str | None = Field(default=None, alias="BOMHeaderBaseUnit", description="Unit of the base quantity.")
    text: str | None = Field(default=None, alias="BOMHeaderText", description="Text of the BOM.")
    valid_from: ODataDate = Field(
        default=None, alias="HeaderValidityStartDate", description="Start of the validity of the BOM."
    )
    valid_to: ODataDate = Field(
        default=None, alias="HeaderValidityEndDate", description="End of the validity of the BOM."
    )
    items: Annotated[
        list[SAPMaterialBOMItemResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_BillOfMaterialItem",
        description="Items (components). None if not requested ($expand), otherwise a (possibly empty) list.",
    )


class SAPMaterialBOMQueryModel(SAPODataQueryModel):
    """Search criteria for material BOMs (API_BILL_OF_MATERIAL_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"material": "Material {direction}"}
    EXPAND: ClassVar[str] = "to_BillOfMaterialItem"
    sort_by: Literal["material"] = Field(default="material", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    materials: Annotated[list[SAPCode] | None, ODataCondition("Material")] = Field(
        default=None, description="Material (product) numbers the BOMs belong to, e.g. ['PUMP-100']."
    )
    plant: Annotated[SAPCode | None, ODataCondition("Plant")] = Field(default=None, description="Plant, e.g. '3000'.")
    usage: Annotated[SAPCode | None, ODataCondition("BillOfMaterialVariantUsage")] = Field(
        default=None, description="BOM usage, e.g. '4' (plant maintenance), '1' (production)."
    )
    expand_items: bool = Field(default=True, description="Also return the items (components) of each BOM.")


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


class SAPEquipmentModel(SAPODataCreateModel):
    """Data to create an SAP equipment (API_EQUIPMENT, OData V2).

    The equipment number is assigned by SAP unless it is given (external number
    assignment - depends on the customizing of the equipment category). The
    construction type (construction_material) connects the equipment to the material
    it is built from - the plant maintenance BOM of this material is the spare parts
    list of the equipment. Serialized equipment is an individual unit of a material
    (material + serial_number). Additional OData properties that are not modelled
    here can be passed with their OData name (e.g. "AuthorizationGroup").

    See: https://api.sap.com/api/API_EQUIPMENT/overview

    """

    # SAP ignores changes of these properties silently (HTTP 204 without a change):
    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Equipment": "the equipment number is the key of the equipment",
        "EquipmentCategory": "SAP ignores changes of the equipment category",
        "FunctionalLocationLabelName": "the installation location is changed by installing / dismantling the equipment",
        "SuperordinateEquipment": "the installation location is changed by installing / dismantling the equipment",
    }

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "EquipmentName": "Centrifugal pump P-100",
                    "EquipmentCategory": "M",
                    "MaintenancePlant": "1010",
                    "MaintenancePlanningPlant": "1010",
                    "MainWorkCenter": "RES-0100",
                    "MainWorkCenterPlant": "1010",
                    "AssetManufacturerName": "ACME Pumps",
                }
            ]
        }
    )

    equipment_id: SAPCode | None = Field(
        default=None,
        alias="Equipment",
        description=(
            "Equipment number for external number assignment. Omit to let SAP assign the number. "
            "It must be in the external number interval of the equipment category (often alphanumeric "
            "only) - otherwise SAP rejects it (IS/042)."
        ),
        max_length=18,
    )
    name: str = Field(
        alias="EquipmentName",
        description="Description of the equipment, e.g. 'Centrifugal pump P-100'.",
        min_length=1,
        max_length=40,
    )
    category: SAPCode = Field(
        alias="EquipmentCategory",
        description="Equipment category, e.g. 'M' (machines) - system specific; copy from an existing equipment if unsure.",
        min_length=1,
        max_length=1,
    )
    technical_object_type: SAPCode | None = Field(
        default=None,
        alias="TechnicalObjectType",
        description="Technical object type (classification), e.g. 'PUMP' - system specific.",
        max_length=10,
    )
    validity_start_date: ODataV2Date = Field(
        default=None,
        alias="ValidityStartDate",
        description="Start of the validity of the equipment data, e.g. '2026-11-01'. SAP defaults it to today.",
    )
    maintenance_plant: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlant",
        description="Maintenance plant - the plant in which the equipment is installed, e.g. '1010'.",
        max_length=4,
    )
    planning_plant: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant - the plant that plans the maintenance work, e.g. '1010'.",
        max_length=4,
    )
    planner_group: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlannerGroup",
        description="Maintenance planner group, e.g. '010' - system specific; copy from an existing equipment if unsure.",
        max_length=3,
    )
    main_work_center: SAPCode | None = Field(
        default=None,
        alias="MainWorkCenter",
        description="Main work center responsible for the maintenance, e.g. 'RES-0100'.",
        max_length=8,
    )
    main_work_center_plant: SAPCode | None = Field(
        default=None,
        alias="MainWorkCenterPlant",
        description="Plant of the main work center, e.g. '1010'.",
        max_length=4,
    )
    functional_location: str | None = Field(
        default=None,
        alias="FunctionalLocationLabelName",
        description="Label of the functional location to install the equipment at, as shown in the SAP UI, e.g. '1010-PU-01'.",
        max_length=40,
    )
    superordinate_equipment: SAPCode | None = Field(
        default=None,
        alias="SuperordinateEquipment",
        description="Superordinate equipment to install the equipment in.",
        max_length=18,
    )
    manufacturer: str | None = Field(
        default=None,
        alias="AssetManufacturerName",
        description="Manufacturer of the equipment.",
        max_length=30,
    )
    manufacturer_model: str | None = Field(
        default=None,
        alias="ManufacturerPartTypeName",
        description="Model (type designation) of the manufacturer.",
        max_length=20,
    )
    manufacturer_serial_number: str | None = Field(
        default=None,
        alias="ManufacturerSerialNumber",
        description="Serial number of the manufacturer.",
        max_length=30,
    )
    manufacturer_part_number: str | None = Field(
        default=None,
        alias="ManufacturerPartNmbr",
        description="Part number of the manufacturer (order number in the manufacturer's catalog). SAP stores it in upper case.",
        max_length=30,
    )
    manufacturer_country: SAPCode | None = Field(
        default=None,
        alias="ManufacturerCountry",
        description="Country of manufacture (country key), e.g. 'US'.",
        max_length=3,
    )
    construction_material: SAPCode | None = Field(
        default=None,
        alias="ConstructionMaterial",
        description=(
            "Construction type - the material (product) the equipment is built from, e.g. 'PUMP-100'. Its "
            "(plant maintenance) BOM serves as the spare parts list of the equipment; see get_material_boms()."
        ),
        max_length=40,
    )
    material: SAPCode | None = Field(
        default=None,
        alias="Material",
        description=(
            "Material (product) number for serialized equipment - an individual unit of this material, "
            "identified by serial_number. Use construction_material to just say what the equipment is built from."
        ),
        max_length=40,
    )
    serial_number: SAPCode | None = Field(
        default=None,
        alias="SerialNumber",
        description="SAP serial number of the unit of `material` (serialized equipment), e.g. 'SN-0001'.",
        max_length=18,
    )
    construction_year: str | None = Field(
        default=None,
        alias="ConstructionYear",
        description="Year of construction, e.g. '2019' (empty to clear it).",
        pattern=r"^(\d{4})?$",
    )
    construction_month: str | None = Field(
        default=None,
        alias="ConstructionMonth",
        description="Month of construction, e.g. '07' (empty to clear it).",
        pattern=r"^(0[1-9]|1[0-2])?$",
    )
    location: SAPCode | None = Field(
        default=None,
        alias="AssetLocation",
        description="Location (site) of the equipment - system specific.",
        max_length=10,
    )
    plant_section: SAPCode | None = Field(
        default=None,
        alias="PlantSection",
        description="Plant section - area of the plant - system specific.",
        max_length=3,
    )
    company_code: SAPCode | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code, e.g. '1010'. Usually derived from the maintenance plant.",
        max_length=4,
    )
    cost_center: SAPCode | None = Field(
        default=None,
        alias="CostCenter",
        description="Cost center that is charged with the maintenance costs.",
        max_length=10,
    )
    operation_start_date: ODataV2Date = Field(
        default=None,
        alias="OperationStartDate",
        description="Start-up date - when the equipment was put into operation, e.g. '2026-11-01'.",
    )
    acquisition_date: ODataV2Date = Field(
        default=None,
        alias="AcquisitionDate",
        description="Date on which the equipment was acquired, e.g. '2026-10-01'.",
    )

    @model_validator(mode="after")
    def check_serial_number(self) -> Self:
        """Check that a serial number comes with its material (serialized equipment)."""

        if self.serial_number and not self.material:
            message = "A serial number needs the material of the serialized equipment (Material)"
            raise ValueError(message)

        return self

    # end method definition


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
    is_marked_for_deletion: bool | None = Field(
        default=None,
        alias="EquipmentIsMarkedForDeletion",
        description="True if the equipment is marked for deletion.",
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
    construction_material: str | None = Field(
        default=None,
        alias="ConstructionMaterial",
        description="Construction type - the material (product) the equipment is built from; see get_material_boms().",
    )
    manufacturer: str | None = Field(
        default=None, alias="AssetManufacturerName", description="Manufacturer of the technical object."
    )
    manufacturer_model: str | None = Field(
        default=None, alias="ManufacturerPartTypeName", description="Model (type designation) of the manufacturer."
    )
    manufacturer_serial_number: str | None = Field(
        default=None, alias="ManufacturerSerialNumber", description="Serial number of the manufacturer."
    )
    manufacturer_part_number: str | None = Field(
        default=None, alias="ManufacturerPartNmbr", description="Part number of the manufacturer."
    )
    manufacturer_country: str | None = Field(
        default=None, alias="ManufacturerCountry", description="Country of manufacture (country key)."
    )
    construction_year: str | None = Field(default=None, alias="ConstructionYear", description="Year of construction.")
    construction_month: str | None = Field(
        default=None, alias="ConstructionMonth", description="Month of construction."
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


class SAPFunctionalLocationModel(SAPODataCreateModel):
    """Data to create an SAP functional location (API_FUNCTIONALLOCATION, OData V2).

    The functional location is identified by its label (e.g. "1010-PU-01"), which
    has to match the edit mask of the structure indicator. SAP derives the superior
    functional location from the label (the label of the superior is its prefix)
    unless superior_label is given. Additional OData properties
    that are not modelled here can be passed with their OData name.

    See: https://api.sap.com/api/API_FUNCTIONALLOCATION/overview

    """

    # SAP ignores changes of the label silently (HTTP 204 without a change):
    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "FunctionalLocation": "the label is the key of the functional location",
        "FunctionalLocationLabelName": "the label is the key of the functional location",
    }

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "FunctionalLocation": "1010-PU-01",
                    "FunctionalLocationName": "Pump station 1",
                    "FuncLocationStructure": "YB1",
                    "FunctionalLocationCategory": "M",
                    "MaintenancePlant": "1010",
                    "MaintenancePlanningPlant": "1010",
                }
            ]
        }
    )

    # SAP takes the label in the key property - FunctionalLocationLabelName is read-only in the API:
    label: str = Field(
        alias="FunctionalLocation",
        description=(
            "Functional location label as shown in the SAP UI, e.g. '1010-PU-01'. Must match the edit mask of the "
            "structure indicator. By convention the label of a child starts with the label of its superior "
            "functional location (e.g. '1010-PU' -> '1010-PU-01')."
        ),
        min_length=1,
        max_length=30,
    )
    name: str = Field(
        alias="FunctionalLocationName",
        description="Description of the functional location, e.g. 'Pump station 1'.",
        min_length=1,
        max_length=40,
    )
    structure: SAPCode = Field(
        alias="FuncLocationStructure",
        description="Structure indicator (defines the edit mask and hierarchy levels of the label) - system specific; copy from an existing functional location if unsure.",
        min_length=1,
        max_length=5,
    )
    category: SAPCode = Field(
        alias="FunctionalLocationCategory",
        description="Functional location category, e.g. 'M' (technical system) - system specific; copy from an existing functional location if unsure.",
        min_length=1,
        max_length=1,
    )
    superior_label: str | None = Field(
        default=None,
        alias="SuperiorFunctionalLocation",
        description=(
            "Internal ID (FunctionalLocation) of the superior (parent) functional location, e.g. '1010-PU' - "
            "the same as its label unless alternative labeling is active. Set it whenever a parent is requested "
            "('under ...'). Without it, SAP derives the superior from the label."
        ),
        max_length=30,
    )
    technical_object_type: SAPCode | None = Field(
        default=None,
        alias="TechnicalObjectType",
        description="Technical object type (classification) - system specific.",
        max_length=10,
    )
    maintenance_plant: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlant",
        description="Maintenance plant - the plant in which the functional location is located, e.g. '1010'.",
        max_length=4,
    )
    planning_plant: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlanningPlant",
        description="Maintenance planning plant - the plant that plans the maintenance work, e.g. '1010'.",
        max_length=4,
    )
    planner_group: SAPCode | None = Field(
        default=None,
        alias="MaintenancePlannerGroup",
        description="Maintenance planner group, e.g. '010' - system specific; copy from an existing functional location if unsure.",
        max_length=3,
    )
    main_work_center: SAPCode | None = Field(
        default=None,
        alias="MainWorkCenter",
        description="Main work center responsible for the maintenance, e.g. 'RES-0100'.",
        max_length=8,
    )
    main_work_center_plant: SAPCode | None = Field(
        default=None,
        alias="MainWorkCenterPlant",
        description="Plant of the main work center, e.g. '1010'.",
        max_length=4,
    )
    location: SAPCode | None = Field(
        default=None,
        alias="AssetLocation",
        description="Location (site) of the functional location - system specific.",
        max_length=10,
    )
    plant_section: SAPCode | None = Field(
        default=None,
        alias="PlantSection",
        description="Plant section - area of the plant - system specific.",
        max_length=3,
    )
    company_code: SAPCode | None = Field(
        default=None,
        alias="CompanyCode",
        description="Company code, e.g. '1010'. Usually derived from the maintenance plant.",
        max_length=4,
    )
    cost_center: SAPCode | None = Field(
        default=None,
        alias="CostCenter",
        description="Cost center that is charged with the maintenance costs.",
        max_length=10,
    )
    manufacturer: str | None = Field(
        default=None,
        alias="AssetManufacturerName",
        description="Manufacturer of the functional location (e.g. of a system bought as a whole).",
        max_length=30,
    )
    manufacturer_model: str | None = Field(
        default=None,
        alias="ManufacturerPartTypeName",
        description="Model (type designation) of the manufacturer.",
        max_length=20,
    )
    manufacturer_part_number: str | None = Field(
        default=None,
        alias="ManufacturerPartNmbr",
        description="Part number of the manufacturer (order number in the manufacturer's catalog). SAP stores it in upper case.",
        max_length=30,
    )
    manufacturer_country: SAPCode | None = Field(
        default=None,
        alias="ManufacturerCountry",
        description="Country of manufacture (country key), e.g. 'US'.",
        max_length=3,
    )
    equipment_installation_allowed: bool | None = Field(
        default=None,
        alias="EquipmentInstallationIsAllowed",
        description="True if equipment can be installed at the functional location.",
    )
    single_equipment_only: bool | None = Field(
        default=None,
        alias="OnePieceOfEquipmentIsAllowed",
        description="True if only one piece of equipment can be installed at the functional location.",
    )
    operation_start_date: ODataV2Date = Field(
        default=None,
        alias="OperationStartDate",
        description="Start-up date - when the functional location was put into operation, e.g. '2026-11-01'.",
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
    is_marked_for_deletion: bool | None = Field(
        default=None,
        alias="FuncnlLocIsMarkedForDeletion",
        description="True if the functional location is marked for deletion.",
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
    manufacturer: str | None = Field(
        default=None, alias="AssetManufacturerName", description="Manufacturer of the technical object."
    )
    manufacturer_model: str | None = Field(
        default=None, alias="ManufacturerPartTypeName", description="Model (type designation) of the manufacturer."
    )
    manufacturer_part_number: str | None = Field(
        default=None, alias="ManufacturerPartNmbr", description="Part number of the manufacturer."
    )
    manufacturer_country: str | None = Field(
        default=None, alias="ManufacturerCountry", description="Country of manufacture (country key)."
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


class SAPBusinessPartnerAddressModel(SAPODataCreateModel):
    """An address of a new business partner."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "BusinessPartner": "the business partner number is part of the key",
        "AddressID": "the address ID is part of the key",
    }

    # Filled with the number of the business partner (see SAPBusinessPartnerModel.check_business_partner_ids()):
    business_partner_id: SkipJsonSchema[SAPCode | None] = Field(default=None, alias="BusinessPartner", max_length=10)
    country: SAPCode = Field(
        alias="Country",
        description="Country key (ISO), e.g. 'US', 'DE'.",
        min_length=2,
        max_length=3,
    )
    region: SAPCode | None = Field(
        default=None,
        alias="Region",
        description="Region (state, province) - system specific code, e.g. 'TX' (Texas) for the US.",
        max_length=3,
    )
    city: str | None = Field(default=None, alias="CityName", description="City, e.g. 'Houston'.", max_length=40)
    postal_code: SAPCode | None = Field(
        default=None, alias="PostalCode", description="Postal code, e.g. '77001'.", max_length=10
    )
    street: str | None = Field(
        default=None, alias="StreetName", description="Street name (without house number).", max_length=60
    )
    house_number: str | None = Field(default=None, alias="HouseNumber", description="House number.", max_length=10)
    language: SAPCode | None = Field(
        default=None, alias="Language", description="Language key of the address, e.g. 'EN'.", max_length=2
    )


class SAPBusinessPartnerRoleModel(SAPODataCreateModel):
    """A role of a new business partner."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "BusinessPartner": "the business partner number is part of the key",
        "BusinessPartnerRole": "the role is part of the key",
    }

    # Filled with the number of the business partner (see SAPBusinessPartnerModel.check_business_partner_ids()):
    business_partner_id: SkipJsonSchema[SAPCode | None] = Field(default=None, alias="BusinessPartner", max_length=10)
    role: SAPCode = Field(
        alias="BusinessPartnerRole",
        description=(
            "Business partner role, e.g. 'FLVN00' (supplier - general and company code data; enough for a "
            "manufacturer), 'FLVN01' (supplier - purchasing data; in addition to FLVN00 to order from the supplier), "
            "'FLCU00' (customer - general and company code data), 'FLCU01' (customer - sales data), 'BUP001' "
            "(contact person). System specific; copy from a similar business partner if unsure."
        ),
        min_length=1,
        max_length=6,
    )


class SAPSupplierPurchasingOrgModel(SAPODataCreateModel):
    """The purchasing organization data of a new supplier - needed to order from the supplier (role FLVN01)."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Supplier": "the supplier number is part of the key",
        "PurchasingOrganization": "the purchasing organization is part of the key",
    }

    # No supplier number - SAP assigns it when it creates the supplier (it can differ from the business partner
    # number, depending on the customizing of the grouping).
    purchasing_organization: SAPCode = Field(
        alias="PurchasingOrganization",
        description="Purchasing organization the supplier is ordered from, e.g. '3000'.",
        min_length=1,
        max_length=4,
    )
    order_currency: SAPCurrency | None = Field(
        default=None,
        alias="PurchaseOrderCurrency",
        description="Currency of the purchase orders (ISO code), e.g. 'USD'.",
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="PaymentTerms",
        description="Terms of payment key, e.g. 'NT30' (30 days net) - system specific.",
        max_length=4,
    )
    incoterms: SAPCode | None = Field(
        default=None,
        alias="IncotermsClassification",
        description="Incoterms, e.g. 'CPT', 'FOB', 'EXW'.",
        max_length=3,
    )
    incoterms_location: str | None = Field(
        default=None,
        alias="IncotermsLocation1",
        description="Location of the Incoterms, e.g. 'Houston'.",
        max_length=70,
    )
    purchasing_group: SAPCode | None = Field(
        default=None,
        alias="PurchasingGroup",
        description="Purchasing group (buyer) responsible for the supplier, e.g. '001' - system specific.",
        max_length=3,
    )
    schema_group: SAPCode | None = Field(
        default=None,
        alias="CalculationSchemaGroupCode",
        description="Schema group of the supplier (pricing procedure in purchasing), e.g. '01' - system specific.",
        max_length=2,
    )
    gr_based_invoice_verification: bool | None = Field(
        default=None,
        alias="InvoiceIsGoodsReceiptBased",
        description="True if invoices are verified against the goods receipts (GR-based invoice verification).",
    )


class SAPSupplierCompanyModel(SAPODataCreateModel):
    """The company code data of a new supplier - needed to post its invoices and pay it (role FLVN00)."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Supplier": "the supplier number is part of the key",
        "CompanyCode": "the company code is part of the key",
    }

    # No supplier number - SAP assigns it when it creates the supplier (it can differ from the business partner
    # number, depending on the customizing of the grouping).
    company_code: SAPCode = Field(
        alias="CompanyCode",
        description="Company code that posts the invoices of the supplier, e.g. '3000'.",
        min_length=1,
        max_length=4,
    )
    reconciliation_account: SAPCode = Field(
        alias="ReconciliationAccount",
        description="Reconciliation account (G/L account for payables), e.g. '160000' - system specific.",
        min_length=1,
        max_length=10,
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="PaymentTerms",
        description="Terms of payment key, e.g. 'NT30' (30 days net) - system specific.",
        max_length=4,
    )
    payment_methods: SAPCode | None = Field(
        default=None,
        alias="PaymentMethodsList",
        description="Allowed payment methods (one letter each), e.g. 'Q' - system specific.",
        max_length=10,
    )
    check_duplicate_invoices: bool | None = Field(
        default=None,
        alias="IsToBeCheckedForDuplicates",
        description="True if SAP checks invoices of the supplier for duplicates.",
    )


class SAPSupplierModel(SAPODataCreateModel):
    """The supplier data of a new business partner - created together with the business partner.

    SAP creates the supplier itself for the role FLVN00 - this model adds its purchasing
    organization and company code data. The supplier number is assigned by SAP and can
    differ from the business partner number (depending on the customizing of the grouping).

    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Supplier": "the supplier number is the key of the supplier",
    }

    # No supplier number - SAP assigns it when it creates the supplier (it can differ from the business partner
    # number, depending on the customizing of the grouping).
    purchasing_organizations: list[SAPSupplierPurchasingOrgModel] = Field(
        default_factory=list,
        alias="to_SupplierPurchasingOrg",
        description="Purchasing organization data - needed to order from the supplier (needs role FLVN01).",
        exclude_if=is_empty,
    )
    company_codes: list[SAPSupplierCompanyModel] = Field(
        default_factory=list,
        alias="to_SupplierCompany",
        description="Company code data - needed to post invoices of the supplier and pay it.",
        exclude_if=is_empty,
    )


class SAPCustomerSalesAreaTaxModel(SAPODataCreateModel):
    """The tax classification of a new customer in a sales area - used to determine the output tax in sales."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "DepartureCountry": "the departure country is part of the key",
        "CustomerTaxCategory": "the tax category is part of the key",
    }

    # No customer number and sales area - SAP takes them from the customer and sales area.
    departure_country: SAPCode = Field(
        alias="DepartureCountry",
        description="Country the goods are shipped from (country key), e.g. 'US'.",
        min_length=2,
        max_length=3,
    )
    tax_category: SAPCode = Field(
        alias="CustomerTaxCategory",
        description="Tax category (tax condition type), e.g. 'UTXJ' (US sales tax), 'MWST' (VAT) - system specific.",
        min_length=1,
        max_length=4,
    )
    tax_classification: SAPCode = Field(
        alias="CustomerTaxClassification",
        description="Tax classification of the customer, e.g. '1' (taxable), '0' (tax exempt).",
        min_length=1,
        max_length=1,
    )


class SAPCustomerSalesAreaModel(SAPODataCreateModel):
    """The sales area data of a new customer - needed to sell to the customer (role FLCU01)."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "SalesOrganization": "the sales organization is part of the key",
        "DistributionChannel": "the distribution channel is part of the key",
        "Division": "the division is part of the key",
    }

    # No customer number - SAP assigns it when it creates the customer (it can differ from the business partner
    # number, depending on the customizing of the grouping).
    sales_organization: SAPCode = Field(
        alias="SalesOrganization",
        description="Sales organization, e.g. '3000'.",
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
        alias="Division",
        description="Division (product line), e.g. '00'.",
        min_length=1,
        max_length=2,
    )
    currency: SAPCurrency | None = Field(
        default=None,
        alias="Currency",
        description="Currency of the sales documents (ISO code), e.g. 'USD'.",
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="CustomerPaymentTerms",
        description="Terms of payment key, e.g. '0002' - system specific.",
        max_length=4,
    )
    incoterms: SAPCode | None = Field(
        default=None,
        alias="IncotermsClassification",
        description="Incoterms, e.g. 'EXW', 'FOB', 'CPT'.",
        max_length=3,
    )
    incoterms_location: str | None = Field(
        default=None,
        alias="IncotermsLocation1",
        description="Location of the Incoterms, e.g. 'New York'.",
        max_length=70,
    )
    shipping_condition: SAPCode | None = Field(
        default=None,
        alias="ShippingCondition",
        description="Shipping condition, e.g. '01' (standard) - system specific.",
        max_length=2,
    )
    delivering_plant: SAPCode | None = Field(
        default=None,
        alias="SupplyingPlant",
        description="Default delivering plant, e.g. '3000'.",
        max_length=4,
    )
    pricing_procedure: SAPCode | None = Field(
        default=None,
        alias="CustomerPricingProcedure",
        description="Customer pricing procedure, e.g. '1' (standard) - system specific.",
        max_length=2,
    )
    price_group: SAPCode | None = Field(
        default=None,
        alias="CustomerPriceGroup",
        description="Customer price group, e.g. 'C2' - system specific.",
        max_length=2,
    )
    account_assignment_group: SAPCode | None = Field(
        default=None,
        alias="CustomerAccountAssignmentGroup",
        description="Account assignment group (revenue accounts), e.g. '01' (domestic revenues) - system specific.",
        max_length=2,
    )
    sales_district: SAPCode | None = Field(
        default=None,
        alias="SalesDistrict",
        description="Sales district, e.g. 'US0003' - system specific.",
        max_length=6,
    )
    customer_group: SAPCode | None = Field(
        default=None,
        alias="CustomerGroup",
        description="Customer group, e.g. '01' - system specific.",
        max_length=2,
    )
    taxes: list[SAPCustomerSalesAreaTaxModel] = Field(
        default_factory=list,
        alias="to_SalesAreaTax",
        description="Tax classifications, e.g. [{'DepartureCountry': 'US', 'CustomerTaxCategory': 'UTXJ', "
        "'CustomerTaxClassification': '1'}].",
        exclude_if=is_empty,
    )


class SAPCustomerCompanyModel(SAPODataCreateModel):
    """The company code data of a new customer - needed to post its invoices and payments (role FLCU00)."""

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "CompanyCode": "the company code is part of the key",
    }

    # No customer number - SAP assigns it when it creates the customer.
    company_code: SAPCode = Field(
        alias="CompanyCode",
        description="Company code that posts the invoices to the customer, e.g. '3000'.",
        min_length=1,
        max_length=4,
    )
    reconciliation_account: SAPCode = Field(
        alias="ReconciliationAccount",
        description="Reconciliation account (G/L account for receivables), e.g. '140000' - system specific.",
        min_length=1,
        max_length=10,
    )
    payment_terms: SAPCode | None = Field(
        default=None,
        alias="PaymentTerms",
        description="Terms of payment key, e.g. '0001' - system specific.",
        max_length=4,
    )
    payment_methods: SAPCode | None = Field(
        default=None,
        alias="PaymentMethodsList",
        description="Allowed payment methods (one letter each) - system specific.",
        max_length=10,
    )


class SAPCustomerModel(SAPODataCreateModel):
    """The customer data of a new business partner - created together with the business partner.

    SAP creates the customer itself for the role FLCU00 - this model adds its sales area
    and company code data. The customer number is assigned by SAP and can differ from
    the business partner number (depending on the customizing of the grouping). The
    partner functions of a sales area (sold-to, ship-to, bill-to, payer) are not given -
    SAP determines them.

    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "Customer": "the customer number is the key of the customer",
    }

    sales_areas: list[SAPCustomerSalesAreaModel] = Field(
        default_factory=list,
        alias="to_CustomerSalesArea",
        description="Sales area data - needed to sell to the customer (needs role FLCU01).",
        exclude_if=is_empty,
    )
    company_codes: list[SAPCustomerCompanyModel] = Field(
        default_factory=list,
        alias="to_CustomerCompany",
        description="Company code data - needed to post invoices to the customer and its payments.",
        exclude_if=is_empty,
    )


class SAPBusinessPartnerModel(SAPODataCreateModel):
    """Data to create an SAP business partner - an organization (API_BUSINESS_PARTNER, OData V2).

    Addresses, roles and the supplier / customer data are created together with the business
    partner (deep insert). With a supplier or customer role SAP also creates the supplier / customer -
    its number can differ from the business partner number (depending on the customizing
    of the grouping). Typical roles:

    - FLVN00: supplier - general and company code data (enough for the manufacturer of a product)
    - FLVN01: supplier - purchasing data (in addition to FLVN00 to order from the supplier)
    - FLCU00: customer - general and company code data
    - FLCU01: customer - sales data (in addition to FLCU00 to sell to the customer)

    Business partners cannot be deleted with the API.

    See: https://api.sap.com/api/API_BUSINESS_PARTNER/overview

    """

    READ_ONLY_PROPERTIES: ClassVar[dict[str, str]] = {
        "BusinessPartner": "the business partner number is the key of the business partner",
        "BusinessPartnerCategory": "the category of a business partner cannot be changed",
        "BusinessPartnerGrouping": "the grouping of a business partner cannot be changed with the API",
        "to_BusinessPartnerAddress": "the addresses are only created together with the business partner",
        "to_BusinessPartnerRole": "the roles are only created together with the business partner",
        "to_Supplier": "the supplier data is only created together with the business partner",
        "to_Customer": "the customer data is only created together with the business partner",
    }

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "BusinessPartnerGrouping": "0001",
                    "OrganizationBPName1": "ACME Pumps Inc.",
                    "SearchTerm1": "ACME",
                    "Language": "EN",
                    "to_BusinessPartnerAddress": [
                        {"Country": "US", "Region": "TX", "CityName": "Houston", "PostalCode": "77001"}
                    ],
                    "to_BusinessPartnerRole": [{"BusinessPartnerRole": "FLVN00"}, {"BusinessPartnerRole": "FLVN01"}],
                    "to_Supplier": {
                        "to_SupplierPurchasingOrg": [
                            {"PurchasingOrganization": "3000", "PurchaseOrderCurrency": "USD", "PaymentTerms": "NT30"}
                        ],
                        "to_SupplierCompany": [{"CompanyCode": "3000", "ReconciliationAccount": "160000"}],
                    },
                }
            ]
        }
    )

    business_partner_id: SAPCode | None = Field(
        default=None,
        alias="BusinessPartner",
        description=(
            "Business partner number for external number assignment. Omit to let SAP assign the number - "
            "whether a number can be given depends on the grouping."
        ),
        max_length=10,
    )
    # Only organizations are supported for now:
    category: Literal["2"] = Field(
        default="2",
        alias="BusinessPartnerCategory",
        description="Business partner category - '2' (organization).",
    )
    grouping: SAPCode | None = Field(
        default=None,
        alias="BusinessPartnerGrouping",
        description=(
            "Business partner grouping (number range and type), e.g. '0001' - system specific; copy from a similar "
            "business partner if unsure. SAP uses its default grouping if omitted."
        ),
        max_length=4,
    )
    organization_name: str = Field(
        alias="OrganizationBPName1",
        description="Name of the organization, e.g. 'ACME Pumps Inc.'.",
        min_length=1,
        max_length=40,
    )
    organization_name_2: str | None = Field(
        default=None,
        alias="OrganizationBPName2",
        description="Second line of the name of the organization (if the name is longer than 40 characters).",
        max_length=40,
    )
    search_term: SAPCode | None = Field(
        default=None,
        alias="SearchTerm1",
        description="Search term (short name, upper case), e.g. 'ACME'.",
        max_length=20,
    )
    language: SAPCode | None = Field(
        default=None,
        alias="Language",
        description="Language key of the business partner, e.g. 'EN'.",
        max_length=2,
    )
    addresses: list[SAPBusinessPartnerAddressModel] = Field(
        default_factory=list,
        alias="to_BusinessPartnerAddress",
        description="Addresses - SAP requires one (at least the country) for a supplier or customer role.",
        exclude_if=is_empty,
    )
    roles: list[SAPBusinessPartnerRoleModel] = Field(
        default_factory=list,
        alias="to_BusinessPartnerRole",
        description=(
            "Roles, e.g. [{'BusinessPartnerRole': 'FLVN00'}] for a manufacturer, FLVN00 and FLVN01 for a supplier "
            "to order from, FLCU00 and FLCU01 for a customer."
        ),
        exclude_if=is_empty,
    )
    supplier: SAPSupplierModel | None = Field(
        default=None,
        alias="to_Supplier",
        description=(
            "Purchasing organization and company code data of the supplier - needed to order from the supplier "
            "and to post its invoices. Needs the role FLVN00 (and FLVN01 for purchasing organizations); copy the "
            "values from a similar supplier if unsure."
        ),
    )
    customer: SAPCustomerModel | None = Field(
        default=None,
        alias="to_Customer",
        description=(
            "Sales area and company code data of the customer - needed to sell to the customer and to post its "
            "invoices. Needs the role FLCU00 (and FLCU01 for sales areas); copy the values from a similar customer "
            "if unsure."
        ),
    )

    @model_validator(mode="after")
    def check_business_partner_ids(self) -> Self:
        """Fill in the business partner number for the addresses and roles (needed with an external number)."""

        for child in [*self.addresses, *self.roles]:
            child.business_partner_id = child.business_partner_id or self.business_partner_id
            if child.business_partner_id != self.business_partner_id:
                message = "The addresses and roles must belong to business partner -> '{}', got -> '{}'".format(
                    self.business_partner_id, child.business_partner_id
                )
                raise ValueError(message)

        return self

    # end method definition

    @model_validator(mode="after")
    def check_address(self) -> Self:
        """Check that a supplier or customer has an address (SAP needs its country)."""

        if not self.addresses and any(role.role.startswith(("FLVN", "FLCU")) for role in self.roles):
            message = "A business partner with a supplier or customer role needs an address (at least the country)"
            raise ValueError(message)

        return self

    # end method definition

    @model_validator(mode="after")
    def check_supplier_roles(self) -> Self:
        """Check that the supplier data comes with the supplier roles it needs (FLVN00 / FLVN01)."""

        if not self.supplier:
            return self

        roles = {role.role for role in self.roles}
        if "FLVN00" not in roles:
            message = "Supplier data needs the business partner role FLVN00 (supplier)"
            raise ValueError(message)
        if self.supplier.purchasing_organizations and "FLVN01" not in roles:
            message = "Purchasing organization data needs the business partner role FLVN01 (supplier - purchasing)"
            raise ValueError(message)

        return self

    # end method definition

    @model_validator(mode="after")
    def check_customer_roles(self) -> Self:
        """Check that the customer data comes with the customer roles it needs (FLCU00 / FLCU01)."""

        if not self.customer:
            return self

        roles = {role.role for role in self.roles}
        if "FLCU00" not in roles:
            message = "Customer data needs the business partner role FLCU00 (customer)"
            raise ValueError(message)
        if self.customer.sales_areas and "FLCU01" not in roles:
            message = "Sales area data needs the business partner role FLCU01 (customer - sales)"
            raise ValueError(message)

        return self

    # end method definition


class SAPBusinessPartnerAddressResponseModel(SAPODataModel):
    """An address of a business partner as returned by SAP (API_BUSINESS_PARTNER)."""

    business_partner_id: str = Field(alias="BusinessPartner", description="Business partner number.")
    address_id: str | None = Field(default=None, alias="AddressID", description="Address number.")
    country: str | None = Field(default=None, alias="Country", description="Country key (ISO), e.g. 'US'.")
    region: str | None = Field(default=None, alias="Region", description="Region (state, province), e.g. 'TX'.")
    city: str | None = Field(default=None, alias="CityName", description="City.")
    postal_code: str | None = Field(default=None, alias="PostalCode", description="Postal code.")
    street: str | None = Field(default=None, alias="StreetName", description="Street name.")
    house_number: str | None = Field(default=None, alias="HouseNumber", description="House number.")


class SAPSupplierPurchasingOrgResponseModel(SAPODataModel):
    """The purchasing organization data of a supplier as returned by SAP (API_BUSINESS_PARTNER)."""

    supplier_id: str = Field(alias="Supplier", description="Supplier number.")
    purchasing_organization: str = Field(alias="PurchasingOrganization", description="Purchasing organization.")
    order_currency: str | None = Field(
        default=None, alias="PurchaseOrderCurrency", description="Currency of the purchase orders."
    )
    payment_terms: str | None = Field(default=None, alias="PaymentTerms", description="Terms of payment key.")
    incoterms: str | None = Field(default=None, alias="IncotermsClassification", description="Incoterms.")
    incoterms_location: str | None = Field(
        default=None, alias="IncotermsLocation1", description="Location of the Incoterms."
    )
    purchasing_group: str | None = Field(
        default=None, alias="PurchasingGroup", description="Purchasing group (buyer) responsible for the supplier."
    )
    schema_group: str | None = Field(
        default=None, alias="CalculationSchemaGroupCode", description="Schema group of the supplier."
    )
    gr_based_invoice_verification: bool | None = Field(
        default=None, alias="InvoiceIsGoodsReceiptBased", description="True if GR-based invoice verification is used."
    )
    is_blocked: bool | None = Field(
        default=None,
        alias="PurchasingIsBlockedForSupplier",
        description="True if purchasing is blocked for the supplier in this purchasing organization.",
    )


class SAPSupplierCompanyResponseModel(SAPODataModel):
    """The company code data of a supplier as returned by SAP (API_BUSINESS_PARTNER)."""

    supplier_id: str = Field(alias="Supplier", description="Supplier number.")
    company_code: str = Field(alias="CompanyCode", description="Company code; see get_company_code().")
    reconciliation_account: str | None = Field(
        default=None, alias="ReconciliationAccount", description="Reconciliation account (G/L account for payables)."
    )
    payment_terms: str | None = Field(default=None, alias="PaymentTerms", description="Terms of payment key.")
    payment_methods: str | None = Field(
        default=None, alias="PaymentMethodsList", description="Allowed payment methods (one letter each)."
    )
    check_duplicate_invoices: bool | None = Field(
        default=None, alias="IsToBeCheckedForDuplicates", description="True if invoices are checked for duplicates."
    )
    is_blocked_for_posting: bool | None = Field(
        default=None, alias="SupplierIsBlockedForPosting", description="True if posting is blocked in the company code."
    )


class SAPSupplierResponseModel(SAPODataModel):
    """The supplier data of a business partner as returned by SAP (API_BUSINESS_PARTNER).

    Attributes:
        purchasing_organizations / company_codes:
            None if they have not been requested ($expand), otherwise a (possibly empty) list.

    """

    supplier_id: str = Field(alias="Supplier", description="Supplier number.")
    account_group: str | None = Field(
        default=None, alias="SupplierAccountGroup", description="Supplier account group (derived from the grouping)."
    )
    purchasing_organizations: Annotated[
        list[SAPSupplierPurchasingOrgResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_SupplierPurchasingOrg",
        description="Purchasing organization data. None if not requested ($expand).",
    )
    company_codes: Annotated[
        list[SAPSupplierCompanyResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_SupplierCompany",
        description="Company code data. None if not requested ($expand).",
    )


class SAPCustomerSalesAreaTaxResponseModel(SAPODataModel):
    """The tax classification of a customer in a sales area as returned by SAP (API_BUSINESS_PARTNER)."""

    departure_country: str | None = Field(
        default=None, alias="DepartureCountry", description="Country the goods are shipped from."
    )
    tax_category: str | None = Field(
        default=None, alias="CustomerTaxCategory", description="Tax category (tax condition type), e.g. 'UTXJ'."
    )
    tax_classification: str | None = Field(
        default=None, alias="CustomerTaxClassification", description="Tax classification, e.g. '1' (taxable)."
    )


class SAPCustomerPartnerFunctionResponseModel(SAPODataModel):
    """A partner function of a customer in a sales area as returned by SAP (API_BUSINESS_PARTNER)."""

    partner_function: str | None = Field(
        default=None,
        alias="PartnerFunction",
        description="Partner function, e.g. 'SP' (sold-to), 'SH' (ship-to), 'BP' (bill-to), 'PY' (payer).",
    )
    partner_customer_id: str | None = Field(
        default=None, alias="BPCustomerNumber", description="Customer number of the partner."
    )


class SAPCustomerSalesAreaResponseModel(SAPODataModel):
    """The sales area data of a customer as returned by SAP (API_BUSINESS_PARTNER)."""

    customer_id: str = Field(alias="Customer", description="Customer number.")
    sales_organization: str = Field(alias="SalesOrganization", description="Sales organization.")
    distribution_channel: str = Field(alias="DistributionChannel", description="Distribution channel.")
    division: str = Field(alias="Division", description="Division.")
    currency: str | None = Field(default=None, alias="Currency", description="Currency of the sales documents.")
    payment_terms: str | None = Field(default=None, alias="CustomerPaymentTerms", description="Terms of payment key.")
    incoterms: str | None = Field(default=None, alias="IncotermsClassification", description="Incoterms.")
    incoterms_location: str | None = Field(
        default=None, alias="IncotermsLocation1", description="Location of the Incoterms."
    )
    shipping_condition: str | None = Field(default=None, alias="ShippingCondition", description="Shipping condition.")
    delivering_plant: str | None = Field(default=None, alias="SupplyingPlant", description="Default delivering plant.")
    pricing_procedure: str | None = Field(
        default=None, alias="CustomerPricingProcedure", description="Customer pricing procedure."
    )
    price_group: str | None = Field(default=None, alias="CustomerPriceGroup", description="Customer price group.")
    account_assignment_group: str | None = Field(
        default=None, alias="CustomerAccountAssignmentGroup", description="Account assignment group."
    )
    sales_district: str | None = Field(default=None, alias="SalesDistrict", description="Sales district.")
    customer_group: str | None = Field(default=None, alias="CustomerGroup", description="Customer group.")
    taxes: Annotated[
        list[SAPCustomerSalesAreaTaxResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None, alias="to_SalesAreaTax", description="Tax classifications. None if not requested ($expand)."
    )
    partner_functions: Annotated[
        list[SAPCustomerPartnerFunctionResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_PartnerFunction",
        description="Partner functions (sold-to, ship-to, bill-to, payer). None if not requested ($expand).",
    )


class SAPCustomerCompanyResponseModel(SAPODataModel):
    """The company code data of a customer as returned by SAP (API_BUSINESS_PARTNER)."""

    customer_id: str = Field(alias="Customer", description="Customer number.")
    company_code: str = Field(alias="CompanyCode", description="Company code; see get_company_code().")
    reconciliation_account: str | None = Field(
        default=None, alias="ReconciliationAccount", description="Reconciliation account (G/L account for receivables)."
    )
    payment_terms: str | None = Field(default=None, alias="PaymentTerms", description="Terms of payment key.")
    payment_methods: str | None = Field(
        default=None, alias="PaymentMethodsList", description="Allowed payment methods (one letter each)."
    )


class SAPCustomerResponseModel(SAPODataModel):
    """The customer data of a business partner as returned by SAP (API_BUSINESS_PARTNER).

    Attributes:
        sales_areas / company_codes:
            None if they have not been requested ($expand), otherwise a (possibly empty) list.

    """

    customer_id: str = Field(alias="Customer", description="Customer number.")
    account_group: str | None = Field(
        default=None, alias="CustomerAccountGroup", description="Customer account group (derived from the grouping)."
    )
    sales_areas: Annotated[
        list[SAPCustomerSalesAreaResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None, alias="to_CustomerSalesArea", description="Sales area data. None if not requested ($expand)."
    )
    company_codes: Annotated[
        list[SAPCustomerCompanyResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None, alias="to_CustomerCompany", description="Company code data. None if not requested ($expand)."
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
        description="Supplier (vendor) number - a business partner in the supplier role; see get_suppliers().",
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
    addresses: Annotated[
        list[SAPBusinessPartnerAddressResponseModel] | None,
        BeforeValidator(unwrap_odata_navigation),
    ] = Field(
        default=None,
        alias="to_BusinessPartnerAddress",
        description="Addresses. None if not requested ($expand), otherwise a (possibly empty) list.",
    )
    supplier_data: Annotated[SAPSupplierResponseModel | None, BeforeValidator(unwrap_odata_single_navigation)] = Field(
        default=None,
        alias="to_Supplier",
        description=(
            "Purchasing organization and company code data of the supplier. None if not requested ($expand) or "
            "the business partner is no supplier."
        ),
    )
    customer_data: Annotated[SAPCustomerResponseModel | None, BeforeValidator(unwrap_odata_single_navigation)] = Field(
        default=None,
        alias="to_Customer",
        description=(
            "Sales area and company code data of the customer. None if not requested ($expand) or the business "
            "partner is no customer."
        ),
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


class SAPSupplierQueryModel(SAPBusinessPartnerQueryModel):
    """Search criteria for SAP suppliers (vendors) - business partners with the supplier role (API_BUSINESS_PARTNER)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "supplier": "Supplier {direction}",
        "name": "BusinessPartnerFullName {direction}",
    }
    BASE_CONDITIONS: ClassVar[list[str]] = ["Supplier ne ''"]
    sort_by: Literal["supplier", "name"] = Field(default="supplier", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    supplier_ids: Annotated[list[SAPCode] | None, ODataCondition("Supplier")] = Field(
        default=None, description="Supplier (vendor) numbers, e.g. ['17300001']."
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
    currency: Annotated[SAPCurrency | None, ODataCondition("Currency")] = Field(
        default=None, description="Local currency of the company codes (ISO 4217 code), e.g. 'EUR'."
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
    """Search criteria for SAP sales organizations (API_SALESORGANIZATION_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"sales_organization": "SalesOrganization {direction}"}
    EXPAND: ClassVar[str] = "to_Text"
    TEXT_SEARCH: ClassVar[ODataTextSearch | None] = ODataTextSearch(
        field="name_contains",
        entity_set="A_SalesOrganizationText",
        properties=("SalesOrganizationName",),
        key="SalesOrganization",
        ids_field="sales_organizations",
    )
    sort_by: Literal["sales_organization"] = Field(default="sales_organization", description="Sort criterion.")
    sort_direction: Literal["asc", "desc"] = Field(default="asc", description="Sort direction.")
    sales_organizations: Annotated[list[SAPCode] | None, ODataCondition("SalesOrganization")] = Field(
        default=None, description="Sales organizations, e.g. ['1010']."
    )
    company_code: Annotated[SAPCode | None, ODataCondition("CompanyCode")] = Field(
        default=None, description="Company code of the sales organizations."
    )
    name_contains: str | None = Field(
        default=None, description="Text contained in the name of the sales organization, e.g. 'US'."
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
    """Search criteria for SAP cost centers (API_COSTCENTER_SRV). Cost centers have validity periods - use valid_on for the current ones."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "cost_center": "ControllingArea {direction},CostCenter {direction},ValidityEndDate desc"
    }
    EXPAND: ClassVar[str] = "to_Text"
    TEXT_SEARCH: ClassVar[ODataTextSearch | None] = ODataTextSearch(
        field="name_contains",
        entity_set="A_CostCenterText",
        properties=("CostCenterName", "CostCenterDescription"),
        key="CostCenter",
        ids_field="cost_centers",
        scope=(("controlling_area", "ControllingArea"),),
    )
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
    name_contains: str | None = Field(
        default=None, description="Text contained in the name or description of the cost center, e.g. 'Maint'."
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
    """Search criteria for SAP profit centers (API_PROFITCENTER_SRV). Profit centers have validity periods - use valid_on for the current ones."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {
        "profit_center": "ControllingArea {direction},ProfitCenter {direction},ValidityEndDate desc"
    }
    EXPAND: ClassVar[str] = "to_Text"
    TEXT_SEARCH: ClassVar[ODataTextSearch | None] = ODataTextSearch(
        field="name_contains",
        entity_set="A_ProfitCenterText",
        properties=("ProfitCenterName", "ProfitCenterLongName"),
        key="ProfitCenter",
        ids_field="profit_centers",
        scope=(("controlling_area", "ControllingArea"),),
    )
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
    name_contains: str | None = Field(
        default=None, description="Text contained in the name of the profit center, e.g. 'Sales'."
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
    """Search criteria for SAP G/L accounts of a chart of accounts (API_GLACCOUNTINCHARTOFACCOUNTS_SRV)."""

    SORT_PROPERTIES: ClassVar[dict[str, str]] = {"gl_account": "ChartOfAccounts {direction},GLAccount {direction}"}
    EXPAND: ClassVar[str] = "to_Text"
    TEXT_SEARCH: ClassVar[ODataTextSearch | None] = ODataTextSearch(
        field="name_contains",
        entity_set="A_GLAccountText",
        properties=("GLAccountName", "GLAccountLongName"),
        key="GLAccount",
        ids_field="gl_accounts",
        scope=(("chart_of_accounts", "ChartOfAccounts"),),
    )
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
    name_contains: str | None = Field(
        default=None, description="Text contained in the name of the G/L account, e.g. 'Revenue'."
    )
    expand_items: bool = Field(default=False, description="Also return the names of each G/L account.")
