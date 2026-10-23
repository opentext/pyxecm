"""OData $metadata of SAP S/4HANA services - property types for updates.

SAP checks the JSON format of property values strictly, and the format depends on the OData
version and the request headers (verified in S/4HANA, see the OData JSON format specifications):

* OData V2: Edm.Decimal, Edm.Double, Edm.Single and Edm.Int64 values are JSON strings, Edm.Int32
  values JSON numbers, Edm.DateTime values "/Date(<ms>)/", Edm.Time values ISO 8601 durations
  ("PT08H30M00S"). A JSON number for an Edm.Decimal property is rejected ("Failed to read property").
* OData V4 with "IEEE754Compatible=true" in the Content-Type (always sent by the SAP class):
  Edm.Decimal and Edm.Int64 values are JSON strings - a JSON number is rejected ("Error while
  parsing an XML stream"). Without this parameter, SAP only accepts JSON numbers.
* OData V4 quantities and amounts with a unit / currency annotation (Measures.Unit,
  Measures.ISOCurrency) are only accepted together with their unit / currency
  ("/IWBEP/CM_V4S_RUN/049 Together with property 'X' also property 'Y' needs to be provided").

The functions of this module read these properties from $metadata and convert values into the
format SAP expects - independent of the (create) models, which do not define all properties.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2026, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from datetime import time as dtime
from decimal import Decimal, InvalidOperation

from lxml import etree

from .sap_models import (
    parse_odata_date,
    parse_odata_datetime,
    parse_odata_time,
    serialize_odata_date,
    serialize_odata_datetime,
    serialize_odata_time,
)

SAP_DATA_NAMESPACE = "http://www.sap.com/Protocols/SAPData"

# Edm types whose values are numbers with decimal places / big integers:
DECIMAL_TYPES = {"Edm.Decimal", "Edm.Double", "Edm.Single", "Edm.Int64"}
INTEGER_TYPES = {"Edm.Int32", "Edm.Int16", "Edm.Byte", "Edm.SByte"}
# OData V4 types that are JSON strings with IEEE754Compatible=true (all others stay numbers):
V4_STRING_NUMBER_TYPES = {"Edm.Decimal", "Edm.Int64"}


@dataclass(frozen=True)
class ODataProperty:
    """A property of an OData entity type as defined in $metadata."""

    name: str
    edm_type: str
    is_key: bool = False
    updatable: bool = True
    max_length: int | None = None
    precision: int | None = None
    scale: int | None = None
    # OData V4: the property with the unit / currency of a quantity / amount (Measures annotations):
    unit_property: str | None = None


@dataclass(frozen=True)
class ODataEntityType:
    """An OData entity type (as used by an entity set) with its properties."""

    name: str
    properties: dict[str, ODataProperty] = field(default_factory=dict)


def _term_name(term: str | None) -> str:
    """Return the name of an annotation term without namespace / alias, e.g. "SAP__core.Computed" -> "Computed"."""

    return (term or "").rsplit(".", 1)[-1]


def _annotation_path(annotation: etree._Element) -> str | None:
    """Return the path of a path annotation, e.g. <Annotation Term="Measures.Unit" Path="BaseUnit"/>."""

    if annotation.get("Path"):
        return annotation.get("Path")
    path = next(iter(annotation.iter("{*}Path")), None)

    return path.text if path is not None else None


def parse_odata_metadata(content: bytes, odata_version: int) -> dict[str, ODataEntityType]:
    """Parse the $metadata document of an OData service.

    Args:
        content (bytes):
            The $metadata document (XML).
        odata_version (int):
            The OData version of the service (2 or 4).

    Returns:
        dict[str, ODataEntityType]:
            The entity types by entity set name, e.g. {"A_SalesOrderItem": ODataEntityType(...)}.

    Raises:
        ValueError:
            If the document cannot be parsed.

    """

    try:
        root = etree.fromstring(content)
    except etree.XMLSyntaxError as syntax_error:
        message = "Invalid $metadata document: {}".format(syntax_error)
        raise ValueError(message) from syntax_error

    # Annotations of properties (OData V4 - separate <Annotations Target="Namespace.Type/Property">):
    annotations: dict[tuple[str, str], list[etree._Element]] = {}
    for block in root.iter("{*}Annotations"):
        target = block.get("Target") or ""
        if "/" not in target:
            continue
        type_path, property_name = target.split("/", 1)
        key = (type_path.rsplit(".", 1)[-1], property_name)
        annotations.setdefault(key, []).extend(block.iter("{*}Annotation"))

    entity_types: dict[str, ODataEntityType] = {}
    for type_element in root.iter("{*}EntityType"):
        type_name = type_element.get("Name")
        keys = {key.get("Name") for key in type_element.iter("{*}PropertyRef")}
        properties = {}
        for element in type_element.iter("{*}Property"):
            name = element.get("Name")
            terms = list(element.iter("{*}Annotation")) + annotations.get((type_name, name), [])
            # A boolean annotation without Bool attribute is true:
            computed = any(
                _term_name(term.get("Term")) in {"Computed", "Immutable"}
                and term.get("Bool", "true").lower() != "false"
                for term in terms
            )
            unit = next(
                (
                    _annotation_path(term)
                    for term in terms
                    if _term_name(term.get("Term")) in {"Unit", "ISOCurrency"} and _annotation_path(term)
                ),
                None,
            )
            updatable = element.get("{{{}}}updatable".format(SAP_DATA_NAMESPACE), "true") != "false" and not computed
            # Facets that are no integers (e.g. Scale="variable") are ignored:
            facets = {
                facet: int(value)
                for facet in ("MaxLength", "Precision", "Scale")
                if (value := element.get(facet) or "").isdigit()
            }
            properties[name] = ODataProperty(
                name=name,
                edm_type=element.get("Type") or "Edm.String",
                is_key=name in keys,
                updatable=updatable and name not in keys,
                max_length=facets.get("MaxLength"),
                precision=facets.get("Precision"),
                scale=facets.get("Scale"),
                # SAP only enforces the unit in OData V4 (OData V2 has sap:unit, but accepts quantities alone):
                unit_property=unit if odata_version == 4 else None,
            )
        entity_types[type_name] = ODataEntityType(name=type_name, properties=properties)

    result = {}
    for entity_set in root.iter("{*}EntitySet"):
        type_name = (entity_set.get("EntityType") or "").rsplit(".", 1)[-1]
        if type_name in entity_types:
            result[entity_set.get("Name")] = entity_types[type_name]

    return result


# end function parse_odata_metadata


def _to_decimal(value: object, prop: ODataProperty) -> Decimal:
    """Convert a number (or a string with a number) into a Decimal and check precision and scale."""

    if isinstance(value, bool):
        message = "Property -> '{}' needs a number, not -> {!r}".format(prop.name, value)
        raise ValueError(message)  # noqa: TRY004 - the callers handle invalid values as ValueError
    try:
        number = Decimal(str(value).strip())
    except InvalidOperation as invalid:
        message = "Property -> '{}' needs a number, not -> {!r}".format(prop.name, value)
        raise ValueError(message) from invalid
    if not number.is_finite():
        message = "Property -> '{}' needs a finite number, not -> {!r}".format(prop.name, value)
        raise ValueError(message)

    exponent = number.normalize().as_tuple().exponent
    decimals = -exponent if isinstance(exponent, int) and exponent < 0 else 0
    if prop.edm_type == "Edm.Decimal" and prop.scale is not None and decimals > prop.scale:
        message = "Property -> '{}' allows at most {} decimal place(s), not -> {}".format(prop.name, prop.scale, value)
        raise ValueError(message)
    if prop.edm_type == "Edm.Decimal" and prop.precision is not None:
        integer_digits = len(str(abs(int(number)))) if int(number) else 0
        if integer_digits > prop.precision - (prop.scale or 0):
            message = "Property -> '{}' allows at most {} digit(s) before the decimal point, not -> {}".format(
                prop.name, prop.precision - (prop.scale or 0), value
            )
            raise ValueError(message)
    if prop.edm_type == "Edm.Int64" and number != number.to_integral_value():
        message = "Property -> '{}' needs an integer, not -> {!r}".format(prop.name, value)
        raise ValueError(message)

    return number


def _to_bool(value: object, prop: ODataProperty) -> bool:
    """Convert a boolean (or "true" / "false", "X" / "", 1 / 0) into a bool."""

    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "x", "yes", "1"}:
        return True
    if text in {"false", "", "no", "0"}:
        return False
    message = "Property -> '{}' needs true or false, not -> {!r}".format(prop.name, value)
    raise ValueError(message)


def _to_date(value: object, prop: ODataProperty) -> date:
    """Convert a date (or an ISO 8601 / OData V2 date string) into a date."""

    parsed = parse_odata_date(value) if isinstance(value, str) else value
    if isinstance(parsed, datetime):
        return parsed.date()
    if isinstance(parsed, date):
        return parsed
    try:
        return date.fromisoformat(str(parsed).strip()[:10])
    except ValueError as invalid:
        message = "Property -> '{}' needs a date (YYYY-MM-DD), not -> {!r}".format(prop.name, value)
        raise ValueError(message) from invalid


def _to_datetime(value: object, prop: ODataProperty) -> datetime:
    """Convert a datetime (or an ISO 8601 / OData V2 date string, or a date) into a timezone-aware datetime."""

    parsed = parse_odata_datetime(value) if isinstance(value, str) else value
    if isinstance(parsed, str):
        try:
            parsed = datetime.fromisoformat(parsed.strip())
        except ValueError as invalid:
            message = "Property -> '{}' needs a date and time (ISO 8601), not -> {!r}".format(prop.name, value)
            raise ValueError(message) from invalid
    if isinstance(parsed, datetime):
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    if isinstance(parsed, date):
        return datetime(parsed.year, parsed.month, parsed.day, tzinfo=UTC)
    message = "Property -> '{}' needs a date and time (ISO 8601), not -> {!r}".format(prop.name, value)
    raise ValueError(message)


def _to_time(value: object, prop: ODataProperty) -> dtime:
    """Convert a time (or an ISO 8601 time / OData V2 duration string) into a time."""

    parsed = parse_odata_time(value) if isinstance(value, str) else value
    if isinstance(parsed, dtime):
        return parsed
    try:
        return dtime.fromisoformat(str(parsed).strip())
    except ValueError as invalid:
        message = "Property -> '{}' needs a time (HH:MM:SS), not -> {!r}".format(prop.name, value)
        raise ValueError(message) from invalid


def to_odata_value(prop: ODataProperty, value: object, odata_version: int) -> object:
    """Convert a value into the JSON format SAP expects for the property (see the module documentation).

    Args:
        prop (ODataProperty):
            The property.
        value (object):
            The value, e.g. a number, a numeric string, a date string or a value already in OData format.
        odata_version (int):
            The OData version of the service (2 or 4). OData V4 values are converted for requests
            with "IEEE754Compatible=true".

    Returns:
        object:
            The value for the JSON payload.

    Raises:
        ValueError:
            If the value does not fit the property (type, length, decimal places).

    """

    if value is None:
        return None

    edm_type = prop.edm_type
    if edm_type == "Edm.String":
        if isinstance(value, bool | dict | list):
            message = "Property -> '{}' needs a text, not -> {!r}".format(prop.name, value)
            raise ValueError(message)
        text = format(value, "f") if isinstance(value, Decimal) else str(value)
        if prop.max_length and len(text) > prop.max_length:
            message = "Property -> '{}' allows at most {} characters, not {} -> '{}'".format(
                prop.name, prop.max_length, len(text), text
            )
            raise ValueError(message)
        return text
    if edm_type in DECIMAL_TYPES:
        number = _to_decimal(value, prop)
        if odata_version == 4 and edm_type not in V4_STRING_NUMBER_TYPES:
            return float(number)
        return format(number, "f")
    if edm_type in INTEGER_TYPES:
        number = _to_decimal(value, prop)
        if number != number.to_integral_value():
            message = "Property -> '{}' needs an integer, not -> {!r}".format(prop.name, value)
            raise ValueError(message)
        return int(number)
    if edm_type == "Edm.Boolean":
        return _to_bool(value, prop)
    if edm_type == "Edm.Date":
        return _to_date(value, prop).isoformat()
    if edm_type == "Edm.DateTime":
        # OData V2 - SAP uses it for dates (sap:display-format="Date") and dates with time:
        moment = _to_datetime(value, prop)
        if (moment.hour, moment.minute, moment.second, moment.microsecond) == (0, 0, 0, 0):
            return serialize_odata_date(moment.date())
        return "/Date({})/".format(int(moment.timestamp() * 1000))
    if edm_type == "Edm.DateTimeOffset":
        moment = _to_datetime(value, prop)
        if odata_version == 2:
            return serialize_odata_datetime(moment)
        return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if edm_type == "Edm.Time":
        return serialize_odata_time(_to_time(value, prop))
    if edm_type == "Edm.TimeOfDay":
        return _to_time(value, prop).isoformat()

    # Edm.Guid, enumerations, complex types, ... are sent as given:
    return value


# end function to_odata_value
