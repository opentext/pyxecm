"""PDF renderings of SAP documents in the style of the SAP standard forms.

Used if SAP cannot provide the PDF of a document itself (no output management / form templates
configured), e.g. for billing documents: the document data is read with the OData APIs (see
pyxecm_customizer.sap) and laid out like an SAP form - letterhead (logo), address window, info
block, item table, totals and page numbers.

ReportLab is an optional dependency (extra "forms": pip install pyxecm[forms]). Without it, this
module can still be imported - REPORTLAB_AVAILABLE is False and the render functions raise
RuntimeError.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2026, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import io
import logging
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal

from pyxecm_customizer.sap_models import (
    SAPBillingDocumentResponseModel,
    SAPBusinessPartnerResponseModel,
    SAPCompanyCodeResponseModel,
    SAPGoodsMovementResponseModel,
    SAPMaintenanceOrderResponseModel,
    SAPOutboundDeliveryResponseModel,
    SAPProductionOrderResponseModel,
    SAPPurchaseContractResponseModel,
    SAPPurchaseOrderResponseModel,
    SAPSalesContractResponseModel,
    SAPSalesOrderResponseModel,
)

logger = logging.getLogger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, LETTER
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        NextPageTemplate,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )
except ImportError:  # pragma: no cover - depends on the installation
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab is not installed - SAP documents without an SAP output form cannot be rendered as PDF.")
else:
    REPORTLAB_AVAILABLE = True

# Countries whose documents use US letter paper and US date formats - all others use A4:
LETTER_COUNTRIES = {"US", "CA", "MX", "PH"}

FONT = "Helvetica"
FONT_BOLD = "Helvetica-Bold"

# Columns of the item table after the description that are texts (left-aligned) - the others are
# quantities, dates and amounts (right-aligned):
TEXT_COLUMNS = {"Unit", "Batch", "Plant", "Storage location", "Work center", "Control key", "Movement type"}

# Thousands and decimal separators per country of the sender (like the dates, see format_date()) - all
# other countries use "1,234.56":
NUMBER_SEPARATORS = {
    "DE": (".", ","),
    "AT": (".", ","),
    "IT": (".", ","),
    "ES": (".", ","),
    "NL": (".", ","),
    "BE": (".", ","),
    "PT": (".", ","),
    "BR": (".", ","),
    "DK": (".", ","),
    "FR": ("\u00a0", ","),  # no-break space
    "CH": ("'", "."),
}

# SAP's one-letter language keys (SPRAS) of the form languages - the OData APIs mostly return the
# two-letter ISO codes:
SAP_LANGUAGE_KEYS = {"D": "DE", "E": "EN", "F": "FR", "I": "IT", "S": "ES", "N": "NL", "P": "PT"}

# The texts of the forms in German, French, Italian, Spanish, Dutch and Portuguese - the English text is the
# key (and the text for English and all other languages). Texts with "{}" are templates for values. The form
# data (SAPFormData) keeps the English texts; render_form() translates them into the language of the document:
TRANSLATIONS: dict[str, dict[str, str]] = {
    # Document titles (and the billing document categories, see SAP_SD_DOCUMENT_CATEGORIES):
    "Order Confirmation": {
        "DE": "Auftragsbestätigung",
        "FR": "Confirmation de commande",
        "IT": "Conferma d'ordine",
        "ES": "Confirmación de pedido",
        "NL": "Orderbevestiging",
        "PT": "Confirmação de pedido",
    },
    "Delivery Note": {
        "DE": "Lieferschein",
        "FR": "Bon de livraison",
        "IT": "Documento di trasporto",
        "ES": "Albarán de entrega",
        "NL": "Pakbon",
        "PT": "Nota de entrega",
    },
    "Purchase Order": {
        "DE": "Bestellung",
        "FR": "Commande d'achat",
        "IT": "Ordine d'acquisto",
        "ES": "Pedido de compra",
        "NL": "Inkooporder",
        "PT": "Pedido de compra",
    },
    "Contract Confirmation": {
        "DE": "Kontraktbestätigung",
        "FR": "Confirmation de contrat",
        "IT": "Conferma di contratto",
        "ES": "Confirmación de contrato",
        "NL": "Contractbevestiging",
        "PT": "Confirmação de contrato",
    },
    "Purchase Contract": {
        "DE": "Einkaufskontrakt",
        "FR": "Contrat d'achat",
        "IT": "Contratto d'acquisto",
        "ES": "Contrato de compra",
        "NL": "Inkoopcontract",
        "PT": "Contrato de compra",
    },
    "Work Order": {
        "DE": "Arbeitsauftrag",
        "FR": "Ordre de travail",
        "IT": "Ordine di lavoro",
        "ES": "Orden de trabajo",
        "NL": "Werkorder",
        "PT": "Ordem de serviço",
    },
    "Production Order": {
        "DE": "Fertigungsauftrag",
        "FR": "Ordre de fabrication",
        "IT": "Ordine di produzione",
        "ES": "Orden de fabricación",
        "NL": "Productieorder",
        "PT": "Ordem de produção",
    },
    "Goods Receipt Slip": {
        "DE": "Wareneingangsschein",
        "FR": "Bon d'entrée de marchandises",
        "IT": "Bolla di entrata merci",
        "ES": "Vale de entrada de mercancías",
        "NL": "Goederenontvangstbon",
        "PT": "Guia de entrada de mercadorias",
    },
    "Goods Issue Slip": {
        "DE": "Warenausgangsschein",
        "FR": "Bon de sortie de marchandises",
        "IT": "Bolla di uscita merci",
        "ES": "Vale de salida de mercancías",
        "NL": "Goederenuitgiftebon",
        "PT": "Guia de saída de mercadorias",
    },
    "Transfer Posting Slip": {
        "DE": "Umbuchungsschein",
        "FR": "Bon de transfert",
        "IT": "Bolla di trasferimento",
        "ES": "Vale de traspaso",
        "NL": "Overboekingsbon",
        "PT": "Guia de transferência",
    },
    "Material Document": {
        "DE": "Materialbeleg",
        "FR": "Document article",
        "IT": "Documento materiale",
        "ES": "Documento de material",
        "NL": "Materiaaldocument",
        "PT": "Documento de material",
    },
    "Billing Document": {
        "DE": "Faktura",
        "FR": "Document de facturation",
        "IT": "Documento di fatturazione",
        "ES": "Documento de facturación",
        "NL": "Factuurdocument",
        "PT": "Documento de faturamento",
    },
    "Invoice": {"DE": "Rechnung", "FR": "Facture", "IT": "Fattura", "ES": "Factura", "NL": "Factuur", "PT": "Fatura"},
    "Credit Memo": {
        "DE": "Gutschrift",
        "FR": "Avoir",
        "IT": "Nota di credito",
        "ES": "Abono",
        "NL": "Creditnota",
        "PT": "Nota de crédito",
    },
    "Debit Memo": {
        "DE": "Lastschrift",
        "FR": "Note de débit",
        "IT": "Nota di debito",
        "ES": "Nota de cargo",
        "NL": "Debetnota",
        "PT": "Nota de débito",
    },
    "Invoice Cancellation": {
        "DE": "Rechnungsstorno",
        "FR": "Annulation de facture",
        "IT": "Storno fattura",
        "ES": "Anulación de factura",
        "NL": "Factuurannulering",
        "PT": "Estorno de fatura",
    },
    "Credit Memo Cancellation": {
        "DE": "Gutschriftsstorno",
        "FR": "Annulation d'avoir",
        "IT": "Storno nota di credito",
        "ES": "Anulación de abono",
        "NL": "Annulering creditnota",
        "PT": "Estorno de nota de crédito",
    },
    "Pro Forma Invoice": {
        "DE": "Proformarechnung",
        "FR": "Facture pro forma",
        "IT": "Fattura pro forma",
        "ES": "Factura proforma",
        "NL": "Pro-formafactuur",
        "PT": "Fatura pró-forma",
    },
    "Intercompany Invoice": {
        "DE": "IV-Rechnung",
        "FR": "Facture intersociétés",
        "IT": "Fattura intercompany",
        "ES": "Factura intercompañía",
        "NL": "Intercompany-factuur",
        "PT": "Fatura intercompany",
    },
    "Intercompany Credit Memo": {
        "DE": "IV-Gutschrift",
        "FR": "Avoir intersociétés",
        "IT": "Nota di credito intercompany",
        "ES": "Abono intercompañía",
        "NL": "Intercompany-creditnota",
        "PT": "Nota de crédito intercompany",
    },
    # The number labels of the billing documents ("<title> number"):
    "Billing Document number": {
        "DE": "Fakturanummer",
        "FR": "Numéro de document de facturation",
        "IT": "Numero documento di fatturazione",
        "ES": "Número de documento de facturación",
        "NL": "Factuurdocumentnummer",
        "PT": "Número do documento de faturamento",
    },
    "Invoice number": {
        "DE": "Rechnungsnummer",
        "FR": "Numéro de facture",
        "IT": "Numero fattura",
        "ES": "Número de factura",
        "NL": "Factuurnummer",
        "PT": "Número da fatura",
    },
    "Credit Memo number": {
        "DE": "Gutschriftsnummer",
        "FR": "Numéro d'avoir",
        "IT": "Numero nota di credito",
        "ES": "Número de abono",
        "NL": "Creditnotanummer",
        "PT": "Número da nota de crédito",
    },
    "Debit Memo number": {
        "DE": "Lastschriftsnummer",
        "FR": "Numéro de note de débit",
        "IT": "Numero nota di debito",
        "ES": "Número de nota de cargo",
        "NL": "Debetnotanummer",
        "PT": "Número da nota de débito",
    },
    "Invoice Cancellation number": {
        "DE": "Stornonummer",
        "FR": "Numéro d'annulation",
        "IT": "Numero storno",
        "ES": "Número de anulación",
        "NL": "Annuleringsnummer",
        "PT": "Número do estorno",
    },
    "Credit Memo Cancellation number": {
        "DE": "Stornonummer",
        "FR": "Numéro d'annulation",
        "IT": "Numero storno",
        "ES": "Número de anulación",
        "NL": "Annuleringsnummer",
        "PT": "Número do estorno",
    },
    "Pro Forma Invoice number": {
        "DE": "Proformarechnungsnummer",
        "FR": "Numéro de facture pro forma",
        "IT": "Numero fattura pro forma",
        "ES": "Número de factura proforma",
        "NL": "Pro-formafactuurnummer",
        "PT": "Número da fatura pró-forma",
    },
    "Intercompany Invoice number": {
        "DE": "IV-Rechnungsnummer",
        "FR": "Numéro de facture intersociétés",
        "IT": "Numero fattura intercompany",
        "ES": "Número de factura intercompañía",
        "NL": "Intercompany-factuurnummer",
        "PT": "Número da fatura intercompany",
    },
    "Intercompany Credit Memo number": {
        "DE": "IV-Gutschriftsnummer",
        "FR": "Numéro d'avoir intersociétés",
        "IT": "Numero nota di credito intercompany",
        "ES": "Número de abono intercompañía",
        "NL": "Intercompany-creditnotanummer",
        "PT": "Número da nota de crédito intercompany",
    },
    # Info block:
    "Order number": {
        "DE": "Auftragsnummer",
        "FR": "Numéro de commande",
        "IT": "Numero ordine",
        "ES": "Número de pedido",
        "NL": "Ordernummer",
        "PT": "Número do pedido",
    },
    "Order date": {
        "DE": "Auftragsdatum",
        "FR": "Date de commande",
        "IT": "Data ordine",
        "ES": "Fecha de pedido",
        "NL": "Orderdatum",
        "PT": "Data do pedido",
    },
    "Customer number": {
        "DE": "Kundennummer",
        "FR": "Numéro de client",
        "IT": "Numero cliente",
        "ES": "Número de cliente",
        "NL": "Klantnummer",
        "PT": "Número do cliente",
    },
    "Your reference": {
        "DE": "Ihr Zeichen",
        "FR": "Votre référence",
        "IT": "Vostro riferimento",
        "ES": "Su referencia",
        "NL": "Uw referentie",
        "PT": "Sua referência",
    },
    "Your reference date": {
        "DE": "Ihr Zeichen vom",
        "FR": "Date de votre référence",
        "IT": "Data vostro riferimento",
        "ES": "Fecha de su referencia",
        "NL": "Datum uw referentie",
        "PT": "Data da sua referência",
    },
    "Requested delivery": {
        "DE": "Wunschliefertermin",
        "FR": "Livraison souhaitée",
        "IT": "Consegna richiesta",
        "ES": "Entrega solicitada",
        "NL": "Gewenste levering",
        "PT": "Entrega solicitada",
    },
    "Currency": {"DE": "Währung", "FR": "Devise", "IT": "Valuta", "ES": "Moneda", "NL": "Valuta", "PT": "Moeda"},
    "Date": {"DE": "Datum", "FR": "Date", "IT": "Data", "ES": "Fecha", "NL": "Datum", "PT": "Data"},
    "Sales order": {
        "DE": "Kundenauftrag",
        "FR": "Commande client",
        "IT": "Ordine cliente",
        "ES": "Pedido de cliente",
        "NL": "Verkooporder",
        "PT": "Ordem de venda",
    },
    "Delivery": {
        "DE": "Lieferung",
        "FR": "Livraison",
        "IT": "Consegna",
        "ES": "Entrega",
        "NL": "Levering",
        "PT": "Remessa",
    },
    "Delivery number": {
        "DE": "Liefernummer",
        "FR": "Numéro de livraison",
        "IT": "Numero consegna",
        "ES": "Número de entrega",
        "NL": "Leveringsnummer",
        "PT": "Número da remessa",
    },
    "Delivery date": {
        "DE": "Lieferdatum",
        "FR": "Date de livraison",
        "IT": "Data di consegna",
        "ES": "Fecha de entrega",
        "NL": "Leverdatum",
        "PT": "Data de entrega",
    },
    "Ship-to party": {
        "DE": "Warenempfänger",
        "FR": "Destinataire",
        "IT": "Destinatario merci",
        "ES": "Destinatario de mercancías",
        "NL": "Goederenontvanger",
        "PT": "Recebedor da mercadoria",
    },
    "Shipping point": {
        "DE": "Versandstelle",
        "FR": "Point d'expédition",
        "IT": "Punto di spedizione",
        "ES": "Puesto de expedición",
        "NL": "Verzendpunt",
        "PT": "Local de expedição",
    },
    "Goods issue": {
        "DE": "Warenausgang",
        "FR": "Sortie de marchandises",
        "IT": "Uscita merci",
        "ES": "Salida de mercancías",
        "NL": "Goederenuitgifte",
        "PT": "Saída de mercadorias",
    },
    "Purchase order number": {
        "DE": "Bestellnummer",
        "FR": "Numéro de commande",
        "IT": "Numero ordine d'acquisto",
        "ES": "Número de pedido de compra",
        "NL": "Inkoopordernummer",
        "PT": "Número do pedido de compra",
    },
    "Supplier number": {
        "DE": "Lieferantennummer",
        "FR": "Numéro de fournisseur",
        "IT": "Numero fornitore",
        "ES": "Número de proveedor",
        "NL": "Leveranciersnummer",
        "PT": "Número do fornecedor",
    },
    "Purchasing organization": {
        "DE": "Einkaufsorganisation",
        "FR": "Organisation d'achats",
        "IT": "Organizzazione acquisti",
        "ES": "Organización de compras",
        "NL": "Inkooporganisatie",
        "PT": "Organização de compras",
    },
    "Purchasing group": {
        "DE": "Einkäufergruppe",
        "FR": "Groupe d'acheteurs",
        "IT": "Gruppo acquisti",
        "ES": "Grupo de compras",
        "NL": "Inkoopgroep",
        "PT": "Grupo de compradores",
    },
    "Contract number": {
        "DE": "Kontraktnummer",
        "FR": "Numéro de contrat",
        "IT": "Numero contratto",
        "ES": "Número de contrato",
        "NL": "Contractnummer",
        "PT": "Número do contrato",
    },
    "Contract date": {
        "DE": "Kontraktdatum",
        "FR": "Date du contrat",
        "IT": "Data contratto",
        "ES": "Fecha del contrato",
        "NL": "Contractdatum",
        "PT": "Data do contrato",
    },
    "Valid from": {
        "DE": "Gültig ab",
        "FR": "Valable du",
        "IT": "Valido dal",
        "ES": "Válido desde",
        "NL": "Geldig vanaf",
        "PT": "Válido de",
    },
    "Valid to": {
        "DE": "Gültig bis",
        "FR": "Valable jusqu'au",
        "IT": "Valido fino al",
        "ES": "Válido hasta",
        "NL": "Geldig tot",
        "PT": "Válido até",
    },
    "Order type": {
        "DE": "Auftragsart",
        "FR": "Type d'ordre",
        "IT": "Tipo ordine",
        "ES": "Clase de orden",
        "NL": "Ordersoort",
        "PT": "Tipo de ordem",
    },
    "Priority": {
        "DE": "Priorität",
        "FR": "Priorité",
        "IT": "Priorità",
        "ES": "Prioridad",
        "NL": "Prioriteit",
        "PT": "Prioridade",
    },
    "Notification": {"DE": "Meldung", "FR": "Avis", "IT": "Avviso", "ES": "Aviso", "NL": "Melding", "PT": "Nota"},
    "Planning plant": {
        "DE": "Planungswerk",
        "FR": "Division de planification",
        "IT": "Divisione di pianificazione",
        "ES": "Centro de planificación",
        "NL": "Planningsvestiging",
        "PT": "Centro de planejamento",
    },
    "Basic start": {
        "DE": "Eckstart",
        "FR": "Début de base",
        "IT": "Inizio base",
        "ES": "Inicio extremo",
        "NL": "Basisstart",
        "PT": "Início base",
    },
    "Basic finish": {
        "DE": "Eckende",
        "FR": "Fin de base",
        "IT": "Fine base",
        "ES": "Fin extremo",
        "NL": "Basiseinde",
        "PT": "Fim base",
    },
    "Material": {
        "DE": "Material",
        "FR": "Article",
        "IT": "Materiale",
        "ES": "Material",
        "NL": "Materiaal",
        "PT": "Material",
    },
    "Quantity": {
        "DE": "Menge",
        "FR": "Quantité",
        "IT": "Quantità",
        "ES": "Cantidad",
        "NL": "Hoeveelheid",
        "PT": "Quantidade",
    },
    "Planned start": {
        "DE": "Geplanter Start",
        "FR": "Début planifié",
        "IT": "Inizio pianificato",
        "ES": "Inicio planificado",
        "NL": "Geplande start",
        "PT": "Início planejado",
    },
    "Planned finish": {
        "DE": "Geplantes Ende",
        "FR": "Fin planifiée",
        "IT": "Fine pianificata",
        "ES": "Fin planificado",
        "NL": "Gepland einde",
        "PT": "Fim planejado",
    },
    "Material document": {
        "DE": "Materialbeleg",
        "FR": "Document article",
        "IT": "Documento materiale",
        "ES": "Documento de material",
        "NL": "Materiaaldocument",
        "PT": "Documento de material",
    },
    "Year": {"DE": "Jahr", "FR": "Année", "IT": "Anno", "ES": "Año", "NL": "Jaar", "PT": "Ano"},
    "Posting date": {
        "DE": "Buchungsdatum",
        "FR": "Date comptable",
        "IT": "Data di registrazione",
        "ES": "Fecha de contabilización",
        "NL": "Boekingsdatum",
        "PT": "Data de lançamento",
    },
    "Document date": {
        "DE": "Belegdatum",
        "FR": "Date du document",
        "IT": "Data documento",
        "ES": "Fecha de documento",
        "NL": "Documentdatum",
        "PT": "Data do documento",
    },
    "Delivery note": {
        "DE": "Lieferschein",
        "FR": "Bon de livraison",
        "IT": "Documento di trasporto",
        "ES": "Albarán",
        "NL": "Pakbon",
        "PT": "Nota de entrega",
    },
    "Purchase order": {
        "DE": "Bestellung",
        "FR": "Commande d'achat",
        "IT": "Ordine d'acquisto",
        "ES": "Pedido de compra",
        "NL": "Inkooporder",
        "PT": "Pedido de compra",
    },
    "Order": {"DE": "Auftrag", "FR": "Ordre", "IT": "Ordine", "ES": "Orden", "NL": "Order", "PT": "Ordem"},
    # Columns and table headings:
    "Item": {"DE": "Pos.", "FR": "Poste", "IT": "Pos.", "ES": "Pos.", "NL": "Pos.", "PT": "Item"},
    "Description": {
        "DE": "Bezeichnung",
        "FR": "Désignation",
        "IT": "Descrizione",
        "ES": "Descripción",
        "NL": "Omschrijving",
        "PT": "Descrição",
    },
    "Unit": {"DE": "Einheit", "FR": "Unité", "IT": "Unità", "ES": "Unidad", "NL": "Eenheid", "PT": "Unidade"},
    "Unit price": {
        "DE": "Einzelpreis",
        "FR": "Prix unitaire",
        "IT": "Prezzo unitario",
        "ES": "Precio unitario",
        "NL": "Stukprijs",
        "PT": "Preço unitário",
    },
    "Net value": {
        "DE": "Nettowert",
        "FR": "Valeur nette",
        "IT": "Valore netto",
        "ES": "Valor neto",
        "NL": "Nettowaarde",
        "PT": "Valor líquido",
    },
    "Batch": {"DE": "Charge", "FR": "Lot", "IT": "Partita", "ES": "Lote", "NL": "Batch", "PT": "Lote"},
    "Net price": {
        "DE": "Nettopreis",
        "FR": "Prix net",
        "IT": "Prezzo netto",
        "ES": "Precio neto",
        "NL": "Nettoprijs",
        "PT": "Preço líquido",
    },
    "Target quantity": {
        "DE": "Zielmenge",
        "FR": "Quantité cible",
        "IT": "Quantità target",
        "ES": "Cantidad prevista",
        "NL": "Doelhoeveelheid",
        "PT": "Quantidade prevista",
    },
    "Operation": {
        "DE": "Vorgang",
        "FR": "Opération",
        "IT": "Operazione",
        "ES": "Operación",
        "NL": "Bewerking",
        "PT": "Operação",
    },
    "Work center": {
        "DE": "Arbeitsplatz",
        "FR": "Poste de travail",
        "IT": "Centro di lavoro",
        "ES": "Puesto de trabajo",
        "NL": "Werkplek",
        "PT": "Centro de trabalho",
    },
    "Control key": {
        "DE": "Steuerschlüssel",
        "FR": "Clé de commande",
        "IT": "Chiave di controllo",
        "ES": "Clave de control",
        "NL": "Stuursleutel",
        "PT": "Chave de controle",
    },
    "Planned work": {
        "DE": "Geplante Arbeit",
        "FR": "Travail planifié",
        "IT": "Lavoro pianificato",
        "ES": "Trabajo planificado",
        "NL": "Gepland werk",
        "PT": "Trabalho planejado",
    },
    "Movement type": {
        "DE": "Bewegungsart",
        "FR": "Type de mouvement",
        "IT": "Tipo movimento",
        "ES": "Clase de movimiento",
        "NL": "Bewegingssoort",
        "PT": "Tipo de movimento",
    },
    "Storage location": {
        "DE": "Lagerort",
        "FR": "Magasin",
        "IT": "Ubicazione",
        "ES": "Almacén",
        "NL": "Opslaglocatie",
        "PT": "Depósito",
    },
    "Start": {"DE": "Start", "FR": "Début", "IT": "Inizio", "ES": "Inicio", "NL": "Start", "PT": "Início"},
    "Finish": {"DE": "Ende", "FR": "Fin", "IT": "Fine", "ES": "Fin", "NL": "Einde", "PT": "Fim"},
    "Components": {
        "DE": "Komponenten",
        "FR": "Composants",
        "IT": "Componenti",
        "ES": "Componentes",
        "NL": "Componenten",
        "PT": "Componentes",
    },
    # Totals:
    "Tax": {"DE": "Steuer", "FR": "Taxes", "IT": "Imposta", "ES": "Impuestos", "NL": "Belasting", "PT": "Impostos"},
    "Total amount": {
        "DE": "Gesamtbetrag",
        "FR": "Montant total",
        "IT": "Importo totale",
        "ES": "Importe total",
        "NL": "Totaalbedrag",
        "PT": "Montante total",
    },
    "Total net value": {
        "DE": "Gesamtnettowert",
        "FR": "Valeur nette totale",
        "IT": "Valore netto totale",
        "ES": "Valor neto total",
        "NL": "Totale nettowaarde",
        "PT": "Valor líquido total",
    },
    "Net weight": {
        "DE": "Nettogewicht",
        "FR": "Poids net",
        "IT": "Peso netto",
        "ES": "Peso neto",
        "NL": "Nettogewicht",
        "PT": "Peso líquido",
    },
    "Gross weight": {
        "DE": "Bruttogewicht",
        "FR": "Poids brut",
        "IT": "Peso lordo",
        "ES": "Peso bruto",
        "NL": "Brutogewicht",
        "PT": "Peso bruto",
    },
    "Target value": {
        "DE": "Zielwert",
        "FR": "Valeur cible",
        "IT": "Valore target",
        "ES": "Valor previsto",
        "NL": "Doelwaarde",
        "PT": "Valor previsto",
    },
    # Notes, recipients and body labels:
    "Terms of payment": {
        "DE": "Zahlungsbedingungen",
        "FR": "Conditions de paiement",
        "IT": "Condizioni di pagamento",
        "ES": "Condiciones de pago",
        "NL": "Betalingsvoorwaarden",
        "PT": "Condições de pagamento",
    },
    "Payment reference": {
        "DE": "Zahlungsreferenz",
        "FR": "Référence de paiement",
        "IT": "Riferimento di pagamento",
        "ES": "Referencia de pago",
        "NL": "Betalingskenmerk",
        "PT": "Referência de pagamento",
    },
    "Bill of lading": {
        "DE": "Frachtbrief",
        "FR": "Lettre de voiture",
        "IT": "Lettera di vettura",
        "ES": "Carta de porte",
        "NL": "Vrachtbrief",
        "PT": "Conhecimento de embarque",
    },
    "Delivery to": {
        "DE": "Lieferung an",
        "FR": "Livraison à",
        "IT": "Consegna a",
        "ES": "Entrega a",
        "NL": "Levering aan",
        "PT": "Entrega em",
    },
    "Customer": {"DE": "Kunde", "FR": "Client", "IT": "Cliente", "ES": "Cliente", "NL": "Klant", "PT": "Cliente"},
    "Supplier": {
        "DE": "Lieferant",
        "FR": "Fournisseur",
        "IT": "Fornitore",
        "ES": "Proveedor",
        "NL": "Leverancier",
        "PT": "Fornecedor",
    },
    "Created by": {
        "DE": "Erfasst von",
        "FR": "Créé par",
        "IT": "Creato da",
        "ES": "Creado por",
        "NL": "Aangemaakt door",
        "PT": "Criado por",
    },
    "Technical object": {
        "DE": "Technisches Objekt",
        "FR": "Objet technique",
        "IT": "Oggetto tecnico",
        "ES": "Objeto técnico",
        "NL": "Technisch object",
        "PT": "Objeto técnico",
    },
    "Maintenance plan": {
        "DE": "Wartungsplan",
        "FR": "Plan d'entretien",
        "IT": "Piano di manutenzione",
        "ES": "Plan de mantenimiento",
        "NL": "Onderhoudsplan",
        "PT": "Plano de manutenção",
    },
    "Prices exclude taxes - they are added in the invoice.": {
        "DE": "Die Preise verstehen sich zuzüglich Steuern - diese werden in der Rechnung ausgewiesen.",
        "FR": "Les prix s'entendent hors taxes - celles-ci sont ajoutées sur la facture.",
        "IT": "I prezzi si intendono al netto delle imposte, che vengono aggiunte in fattura.",
        "ES": "Los precios no incluyen impuestos; estos se añaden en la factura.",
        "NL": "Prijzen zijn exclusief belastingen - deze worden op de factuur toegevoegd.",
        "PT": "Os preços não incluem impostos - eles são acrescentados na fatura.",
    },
    "Thank you for your order. We confirm it with the items and prices above.": {
        "DE": "Vielen Dank für Ihren Auftrag. Wir bestätigen ihn mit den oben aufgeführten Positionen und Preisen.",
        "FR": "Nous vous remercions de votre commande, que nous confirmons avec les postes et les prix ci-dessus.",
        "IT": "Grazie per il vostro ordine, che confermiamo con le posizioni e i prezzi sopra indicati.",
        "ES": "Gracias por su pedido. Se lo confirmamos con las posiciones y los precios indicados arriba.",
        "NL": "Hartelijk dank voor uw order. Wij bevestigen deze met de bovenstaande posities en prijzen.",
        "PT": "Agradecemos o seu pedido, que confirmamos com os itens e preços acima.",
    },
    "Please check the goods on receipt and report any damage or shortfall immediately.": {
        "DE": "Bitte prüfen Sie die Ware bei Erhalt und melden Sie Schäden oder Fehlmengen umgehend.",
        "FR": "Veuillez contrôler la marchandise à la réception et signaler immédiatement tout dommage ou manquant.",
        "IT": "Si prega di controllare la merce al ricevimento e di segnalare subito eventuali danni o ammanchi.",
        "ES": "Compruebe la mercancía a la recepción y comunique de inmediato cualquier daño o falta.",
        "NL": "Controleer de goederen bij ontvangst en meld schade of tekorten onmiddellijk.",
        "PT": "Verifique as mercadorias no recebimento e comunique imediatamente qualquer dano ou falta.",
    },
    "Please quote the purchase order number on all delivery notes and invoices.": {
        "DE": "Bitte geben Sie die Bestellnummer auf allen Lieferscheinen und Rechnungen an.",
        "FR": "Veuillez indiquer le numéro de commande sur tous les bons de livraison et toutes les factures.",
        "IT": "Si prega di indicare il numero d'ordine su tutti i documenti di trasporto e le fatture.",
        "ES": "Indique el número de pedido en todos los albaranes y facturas.",
        "NL": "Vermeld het inkoopordernummer op alle pakbonnen en facturen.",
        "PT": "Indique o número do pedido de compra em todas as notas de entrega e faturas.",
    },
    "Please quote the contract number on all orders that refer to this contract.": {
        "DE": "Bitte geben Sie die Kontraktnummer auf allen Aufträgen zu diesem Kontrakt an.",
        "FR": "Veuillez indiquer le numéro de contrat sur toutes les commandes relatives à ce contrat.",
        "IT": "Si prega di indicare il numero di contratto su tutti gli ordini relativi a questo contratto.",
        "ES": "Indique el número de contrato en todos los pedidos relativos a este contrato.",
        "NL": "Vermeld het contractnummer op alle orders die op dit contract betrekking hebben.",
        "PT": "Indique o número do contrato em todos os pedidos referentes a este contrato.",
    },
    "Please quote the contract number on all deliveries and invoices that refer to this contract.": {
        "DE": "Bitte geben Sie die Kontraktnummer auf allen Lieferungen und Rechnungen zu diesem Kontrakt an.",
        "FR": "Veuillez indiquer le numéro de contrat sur toutes les livraisons et factures relatives à ce contrat.",
        "IT": "Si prega di indicare il numero di contratto su tutte le consegne e le fatture relative a questo contratto.",
        "ES": "Indique el número de contrato en todas las entregas y facturas relativas a este contrato.",
        "NL": "Vermeld het contractnummer op alle leveringen en facturen die op dit contract betrekking hebben.",
        "PT": "Indique o número do contrato em todas as remessas e faturas referentes a este contrato.",
    },
    "Please confirm the work and the time spent per operation when the work is done.": {
        "DE": "Bitte melden Sie nach Abschluss der Arbeiten die Arbeit und den Zeitaufwand je Vorgang zurück.",
        "FR": "Veuillez confirmer le travail et le temps passé par opération une fois le travail terminé.",
        "IT": "Si prega di confermare il lavoro e il tempo impiegato per ogni operazione al termine dei lavori.",
        "ES": "Notifique el trabajo y el tiempo empleado por operación una vez finalizado el trabajo.",
        "NL": "Meld na afronding van de werkzaamheden het werk en de bestede tijd per bewerking terug.",
        "PT": "Confirme o trabalho e o tempo gasto por operação quando o trabalho estiver concluído.",
    },
    "Please confirm the yield and the activities per operation.": {
        "DE": "Bitte melden Sie die Gutmenge und die Leistungen je Vorgang zurück.",
        "FR": "Veuillez confirmer la quantité bonne et les activités par opération.",
        "IT": "Si prega di confermare la quantità buona e le attività per ogni operazione.",
        "ES": "Notifique la cantidad buena y las actividades por operación.",
        "NL": "Meld de goedhoeveelheid en de activiteiten per bewerking terug.",
        "PT": "Confirme a quantidade boa e as atividades por operação.",
    },
    # Templates with values:
    "This contract is valid from {} to {}.": {
        "DE": "Dieser Kontrakt gilt vom {} bis {}.",
        "FR": "Ce contrat est valable du {} au {}.",
        "IT": "Il presente contratto è valido dal {} al {}.",
        "ES": "Este contrato es válido del {} al {}.",
        "NL": "Dit contract is geldig van {} tot {}.",
        "PT": "Este contrato é válido de {} a {}.",
    },
    "Page {} of {}": {
        "DE": "Seite {} von {}",
        "FR": "Page {} sur {}",
        "IT": "Pagina {} di {}",
        "ES": "Página {} de {}",
        "NL": "Pagina {} van {}",
        "PT": "Página {} de {}",
    },
    "{} {} of {}": {
        "DE": "{} {} vom {}",
        "FR": "{} {} du {}",
        "IT": "{} {} del {}",
        "ES": "{} {} del {}",
        "NL": "{} {} van {}",
        "PT": "{} {} de {}",
    },
    "Company code {}": {
        "DE": "Buchungskreis {}",
        "FR": "Société {}",
        "IT": "Società {}",
        "ES": "Sociedad {}",
        "NL": "Bedrijfsnummer {}",
        "PT": "Empresa {}",
    },
    "Sales organization {}": {
        "DE": "Verkaufsorganisation {}",
        "FR": "Organisation commerciale {}",
        "IT": "Organizzazione commerciale {}",
        "ES": "Organización de ventas {}",
        "NL": "Verkooporganisatie {}",
        "PT": "Organização de vendas {}",
    },
    "Shipping point {}": {
        "DE": "Versandstelle {}",
        "FR": "Point d'expédition {}",
        "IT": "Punto di spedizione {}",
        "ES": "Puesto de expedición {}",
        "NL": "Verzendpunt {}",
        "PT": "Local de expedição {}",
    },
    "Plant {}": {
        "DE": "Werk {}",
        "FR": "Division {}",
        "IT": "Divisione {}",
        "ES": "Centro {}",
        "NL": "Vestiging {}",
        "PT": "Centro {}",
    },
    "plant {}": {
        "DE": "Werk {}",
        "FR": "division {}",
        "IT": "divisione {}",
        "ES": "centro {}",
        "NL": "vestiging {}",
        "PT": "centro {}",
    },
    "Production plant {}": {
        "DE": "Produktionswerk {}",
        "FR": "Division de production {}",
        "IT": "Divisione di produzione {}",
        "ES": "Centro de producción {}",
        "NL": "Productievestiging {}",
        "PT": "Centro de produção {}",
    },
    "Work center {}": {
        "DE": "Arbeitsplatz {}",
        "FR": "Poste de travail {}",
        "IT": "Centro di lavoro {}",
        "ES": "Puesto de trabajo {}",
        "NL": "Werkplek {}",
        "PT": "Centro de trabalho {}",
    },
    "MRP controller {}": {
        "DE": "Disponent {}",
        "FR": "Gestionnaire MRP {}",
        "IT": "Responsabile MRP {}",
        "ES": "Planificador de necesidades {}",
        "NL": "MRP-planner {}",
        "PT": "Planejador MRP {}",
    },
    "Storage location {}": {
        "DE": "Lagerort {}",
        "FR": "Magasin {}",
        "IT": "Ubicazione {}",
        "ES": "Almacén {}",
        "NL": "Opslaglocatie {}",
        "PT": "Depósito {}",
    },
    "Equipment {}": {
        "DE": "Equipment {}",
        "FR": "Équipement {}",
        "IT": "Apparecchiatura {}",
        "ES": "Equipo {}",
        "NL": "Equipment {}",
        "PT": "Equipamento {}",
    },
    "Functional location {}": {
        "DE": "Technischer Platz {}",
        "FR": "Poste technique {}",
        "IT": "Sede tecnica {}",
        "ES": "Ubicación técnica {}",
        "NL": "Technische plaats {}",
        "PT": "Local de instalação {}",
    },
}


def translate(text: str, language: str) -> str:
    """Translate a text of the forms into the language of the document (see TRANSLATIONS).

    Args:
        text (str):
            The English text or template, e.g. "Order Confirmation" or "Plant {}".
        language (str):
            The ISO language code of the document, e.g. "DE".

    Returns:
        str:
            The translation - or the English text for English, other languages and texts without
            a translation (e.g. values).

    """

    return TRANSLATIONS.get(text, {}).get(language, text)


# end function translate


def get_language(*languages: str | None) -> str:
    """Get the language of a document - the first language that is set, e.g. the one of the recipient.

    Args:
        *languages (str | None):
            The candidates in order of priority, as ISO codes (e.g. "DE") or SAP's one-letter
            language keys (e.g. "D").

    Returns:
        str:
            The ISO language code (upper case), "EN" if none is set.

    """

    for language in languages:
        language = (language or "").strip().upper()
        if language:
            return SAP_LANGUAGE_KEYS.get(language, language)

    return "EN"


# end function get_language


def get_partner_language(partner: SAPBusinessPartnerResponseModel | None) -> str | None:
    """Get the correspondence language of a business partner - the one of its address, else its own.

    Args:
        partner (SAPBusinessPartnerResponseModel | None):
            The business partner with its addresses.

    Returns:
        str | None:
            The language key or None if not set.

    """

    if not partner:
        return None
    address = next(iter(partner.addresses or []), None)

    return (address.language if address else None) or partner.language


# end function get_partner_language


@dataclass
class SAPFormData:
    """The content of a rendered SAP document - independent of the document type.

    Attributes:
        title (str):
            The document title, e.g. "Invoice" or "Purchase Order".
        number (str):
            The document number - shown in the header of the following pages.
        document_date (date | None):
            The document date.
        sender (list[str]):
            The company: name first, then further address lines (letterhead and sender line).
        recipient (list[str]):
            The address of the recipient (address window).
        info (list[tuple[str, str]]):
            The info block, e.g. [("Invoice number", "90000071"), ("Customer number", "53574")].
        columns (list[str]):
            The headers of the item table.
        rows (list[list[str]]):
            The items. The column "Description" may contain longer texts (wrapped).
        totals (list[tuple[str, str]]):
            The totals below the items, e.g. [("Net value", "8,901.00 USD")]. The last one is printed bold.
        body (list[str]):
            Paragraphs between the title and the items, e.g. the description of a work order.
        tables (list[tuple[str, list[str], list[list[str]]]]):
            Further tables after the items as (heading, columns, rows), e.g. the components of a
            work order.
        notes (list[tuple[str, str]]):
            Terms and references below the totals, e.g. [("Terms of payment", "0001")]. Notes without
            a label are printed as plain sentences.
        footer (str):
            Text of the footer line on every page.
        country (str):
            The country of the sender - selects the date format (and the paper size if the
            country of the recipient is unknown).
        recipient_country (str):
            The country of the recipient - selects the paper size: US letter for North America,
            A4 for all other countries.
        language (str):
            The ISO language code of the document, e.g. "DE" - the texts above are given in English
            and translated by render_form() (see TRANSLATIONS).

    """

    title: str
    number: str
    document_date: date | None
    sender: list[str]
    recipient: list[str]
    info: list[tuple[str, str]] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    totals: list[tuple[str, str]] = field(default_factory=list)
    body: list[str] = field(default_factory=list)
    tables: list[tuple[str, list[str], list[list[str]]]] = field(default_factory=list)
    notes: list[tuple[str, str]] = field(default_factory=list)
    footer: str = ""
    country: str = ""
    recipient_country: str = ""
    language: str = "EN"


def format_date(value: date | datetime | None, country: str) -> str:
    """Format a date as usual in the country of the sender (e.g. 03/08/2016 in the US, 08.03.2016 elsewhere).

    Args:
        value (date | datetime | None):
            The date (of a timestamp only the date is printed).
        country (str):
            The ISO country code of the sender.

    Returns:
        str:
            The formatted date or "" if no date is given.

    """

    if value is None:
        return ""

    return value.strftime("%m/%d/%Y" if country in LETTER_COUNTRIES else "%d.%m.%Y")


# end function format_date


def localize_number(number: str, country: str) -> str:
    """Use the thousands and decimal separators of a country in a number formatted as "1,234.56".

    Args:
        number (str):
            The number with "," as thousands and "." as decimal separator.
        country (str):
            The ISO country code of the sender (see NUMBER_SEPARATORS).

    Returns:
        str:
            The number, e.g. "1.234,56" for Germany.

    """

    thousands, decimal = NUMBER_SEPARATORS.get(country, (",", "."))

    return number.replace(",", "\0").replace(".", decimal).replace("\0", thousands)


# end function localize_number


def format_amount(value: Decimal | float | str | None, country: str = "") -> str:
    """Format an amount with thousands separators and two decimals, e.g. "8,901.00" ("8.901,00" in Germany).

    Args:
        value (Decimal | float | str | None):
            The amount.
        country (str, optional):
            The ISO country code of the sender - selects the separators. Defaults to "" ("8,901.00").

    Returns:
        str:
            The formatted amount or "" if no amount is given.

    """

    if value is None or value == "":
        return ""

    return localize_number("{:,.2f}".format(Decimal(str(value))), country)


# end function format_amount


def format_quantity(value: Decimal | float | str | None, country: str = "") -> str:
    """Format a quantity without decimals for whole numbers, e.g. "1" or "2.5" ("2,5" in Germany).

    Args:
        value (Decimal | float | str | None):
            The quantity.
        country (str, optional):
            The ISO country code of the sender - selects the separators. Defaults to "" ("2.5").

    Returns:
        str:
            The formatted quantity or "" if no quantity is given.

    """

    if value is None or value == "":
        return ""

    quantity = Decimal(str(value))

    return localize_number(
        "{:,.0f}".format(quantity) if quantity == quantity.to_integral() else "{:,}".format(quantity.normalize()),
        country,
    )


# end function format_quantity


def load_logo(logo: str | bytes | None) -> "ImageReader | None":
    """Load the logo for the letterhead.

    Args:
        logo (str | bytes | None):
            The path or the content of a PNG / JPEG image.

    Returns:
        ImageReader | None:
            The image or None if no logo is given or it cannot be read (logged as warning).

    """

    if not logo:
        return None

    try:
        image = ImageReader(io.BytesIO(logo) if isinstance(logo, bytes) else logo)
        image.getSize()  # reads the image - fails for missing or invalid files
    except Exception as exception:
        logger.warning(
            "Cannot read the logo for SAP forms -> %s; error -> %s",
            logo if isinstance(logo, str) else "<bytes>",
            exception,
        )
        return None

    return image


# end function load_logo


def render_form(data: SAPFormData, logo: str | bytes | None = None) -> bytes:
    """Render a document in the style of the SAP standard forms as PDF.

    Args:
        data (SAPFormData):
            The content of the document.
        logo (str | bytes | None, optional):
            The path or the content of a PNG / JPEG logo, printed top right instead of the company
            name. Defaults to None (company name as text).

    Returns:
        bytes:
            The PDF.

    Raises:
        RuntimeError:
            If ReportLab is not installed.

    """

    if not REPORTLAB_AVAILABLE:
        message = "PDF rendering is not available - the Python package 'reportlab' is not installed."
        raise RuntimeError(message)

    # The paper size of the recipient - the sender's if the recipient's country is unknown:
    page_size = LETTER if (data.recipient_country or data.country) in LETTER_COUNTRIES else A4
    page_width, page_height = page_size
    margin = 0.75 * inch if page_size == LETTER else 20 * mm
    width = page_width - 2 * margin
    grey = colors.HexColor("#5b6670")
    light = colors.HexColor("#e9edf0")
    brand = colors.HexColor("#1f3a5f")
    company = data.sender[0] if data.sender else ""
    sender_line = " · ".join(data.sender)

    def tr(text: str) -> str:
        return translate(text, data.language)

    title = tr(data.title)
    logo_image = load_logo(logo)
    if logo_image:
        # Scale the logo into the letterhead (at most 0.5" high and 2.2" wide) - keeping its aspect ratio:
        logo_width, logo_height = logo_image.getSize()
        scale = min(0.5 * inch / logo_height, 2.2 * inch / logo_width)
        logo_width, logo_height = logo_width * scale, logo_height * scale

    normal = ParagraphStyle("normal", fontName=FONT, fontSize=8.5, leading=10.5)
    notes_style = ParagraphStyle("notes", parent=normal, fontSize=9, leading=12)
    title_style = ParagraphStyle("title", parent=normal, fontName=FONT_BOLD, fontSize=14, leading=18)
    heading_style = ParagraphStyle("heading", parent=normal, fontName=FONT_BOLD, fontSize=10, leading=14, spaceAfter=3)

    class NumberedCanvas(canvas.Canvas):
        """Canvas that prints "Page x of y" - the page count is known when the document is saved."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)
            self._saved_pages: list[dict] = []

        def showPage(self) -> None:  # noqa: N802 - ReportLab API
            self._saved_pages.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            for page in self._saved_pages:
                self.__dict__.update(page)
                self.setFont(FONT, 7)
                self.setFillColor(grey)
                self.drawRightString(
                    page_width - margin,
                    0.5 * inch,
                    tr("Page {} of {}").format(self._pageNumber, len(self._saved_pages)),
                )
                super().showPage()
            super().save()

    def letterhead(pdf: canvas.Canvas, doc: BaseDocTemplate) -> None:
        """Draw the parts on every page: company name, rules, footer and (from page 2) the document number."""

        pdf.saveState()
        if logo_image:
            pdf.drawImage(
                logo_image,
                page_width - margin - logo_width,
                page_height - 0.78 * inch,
                width=logo_width,
                height=logo_height,
                mask="auto",
            )
        else:
            pdf.setFont(FONT_BOLD, 16)
            pdf.setFillColor(brand)
            pdf.drawRightString(page_width - margin, page_height - 0.7 * inch, company)
        pdf.setStrokeColor(light)
        pdf.setLineWidth(0.8)
        pdf.line(margin, page_height - 0.85 * inch, page_width - margin, page_height - 0.85 * inch)
        pdf.line(margin, 0.7 * inch, page_width - margin, 0.7 * inch)
        pdf.setFont(FONT, 7)
        pdf.setFillColor(grey)
        pdf.drawString(margin, 0.5 * inch, data.footer or sender_line)
        if doc.page > 1:
            pdf.setFont(FONT, 8.5)
            pdf.setFillColor(colors.black)
            pdf.drawString(
                margin,
                page_height - 1.1 * inch,
                tr("{} {} of {}").format(title, data.number, format_date(data.document_date, data.country)),
            )
        pdf.restoreState()

    def first_page(pdf: canvas.Canvas, doc: BaseDocTemplate) -> None:
        """Draw the address window (sender line and recipient) and the info block on the first page."""

        letterhead(pdf, doc)
        pdf.saveState()
        top = page_height - 1.75 * inch
        pdf.setFont(FONT, 6.5)
        pdf.setFillColor(grey)
        pdf.drawString(margin, top + 14, sender_line)
        pdf.setLineWidth(0.4)
        pdf.line(margin, top + 11, margin + 3.3 * inch, top + 11)
        pdf.setFont(FONT, 10)
        pdf.setFillColor(colors.black)
        for index, line in enumerate(line for line in data.recipient if line):
            pdf.drawString(margin, top - index * 13, line)
        label_x, value_x = page_width - margin - 2.6 * inch, page_width - margin
        for index, (label, value) in enumerate(data.info):
            y = top + 14 - index * 12.5
            pdf.setFont(FONT, 8)
            pdf.setFillColor(grey)
            pdf.drawString(label_x, y, tr(label))
            pdf.setFont(FONT, 8.5)
            pdf.setFillColor(colors.black)
            pdf.drawRightString(value_x, y, value or "-")
        pdf.restoreState()

    buffer = io.BytesIO()
    doc = BaseDocTemplate(
        buffer,
        pagesize=page_size,
        leftMargin=margin,
        rightMargin=margin,
        title="{} {}".format(title, data.number),
        author=company,
    )
    doc.addPageTemplates(
        [
            PageTemplate(
                id="first",
                frames=[Frame(margin, 0.9 * inch, width, page_height - 3.85 * inch, id="first")],
                onPage=first_page,
            ),
            PageTemplate(
                id="next",
                frames=[Frame(margin, 0.9 * inch, width, page_height - 2.2 * inch, id="next")],
                onPage=letterhead,
            ),
        ]
    )

    story = [NextPageTemplate("next"), Paragraph(title, title_style), Spacer(0, 4)]

    def make_table(columns: list[str], table_rows: list[list[str]]) -> "Table":
        """Build a table in the SAP form style - the description takes the remaining width."""

        # Columns without a value in any row are left out (e.g. descriptions that SAP does not return):
        keep = [index for index in range(len(columns)) if index == 0 or any(row[index] for row in table_rows)]
        columns = [columns[index] for index in keep]
        table_rows = [[row[index] for index in keep] for row in table_rows]
        description = columns.index("Description") if "Description" in columns else -1
        rows = [[tr(column) for column in columns]] + [
            [Paragraph(cell, normal) if index == description else cell for index, cell in enumerate(row)]
            for row in table_rows
        ]
        fixed = {
            "Item": 0.45 * inch,
            "Unit": 0.45 * inch,
            "Batch": 1.0 * inch,
            "Operation": 0.7 * inch,
            "Movement type": 1.0 * inch,
            "Storage location": 1.1 * inch,
            "Target quantity": 1.0 * inch,
        }
        widths = [fixed.get(name, 0.9 * inch) if index != description else None for index, name in enumerate(columns)]
        table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
        style = [
            ("FONT", (0, 0), (-1, -1), FONT, 8.5),
            ("FONT", (0, 0), (-1, 0), FONT_BOLD, 8.5),
            ("BACKGROUND", (0, 0), (-1, 0), light),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, grey),
            ("LINEBELOW", (0, 1), (-1, -1), 0.25, light),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        # Quantities, dates and amounts after the description are right-aligned - never the first two
        # columns (item and material), also if there is no description column:
        style += [
            ("ALIGN", (index, 0), (index, -1), "RIGHT")
            for index, name in enumerate(columns)
            if index > max(description, 1) and name not in TEXT_COLUMNS
        ]
        table.setStyle(TableStyle(style))

        return table

    story += [Paragraph(paragraph, notes_style) for paragraph in data.body if paragraph]
    if data.body:
        story.append(Spacer(0, 8))

    if data.columns:
        story += [make_table(data.columns, data.rows), Spacer(0, 10)]

    for heading, columns, table_rows in data.tables:
        if table_rows:
            story += [Paragraph(tr(heading), heading_style), make_table(columns, table_rows), Spacer(0, 10)]

    if data.totals:
        totals = Table(
            [(tr(label), value) for label, value in data.totals], colWidths=[1.6 * inch, 1.4 * inch], hAlign="RIGHT"
        )
        totals.setStyle(
            TableStyle(
                [
                    ("FONT", (0, 0), (-1, -1), FONT, 9),
                    ("FONT", (0, -1), (-1, -1), FONT_BOLD, 9.5),
                    ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                    ("LINEABOVE", (0, -1), (-1, -1), 0.8, colors.black),
                    ("LINEBELOW", (0, -1), (-1, -1), 0.8, colors.black),
                ]
            )
        )
        story += [totals, Spacer(0, 18)]

    story += [
        Paragraph("<b>{}:</b> {}".format(tr(label), value) if label else tr(value), notes_style)
        for label, value in data.notes
        if value
    ]

    doc.build(story, canvasmaker=NumberedCanvas)

    return buffer.getvalue()


# end function render_form


def get_sender_lines(
    company_code: SAPCompanyCodeResponseModel | None, company_code_id: str | None, language: str = "EN"
) -> list[str]:
    """Get the sender (company) lines of a document: name and city / country of the company code.

    Args:
        company_code (SAPCompanyCodeResponseModel | None):
            The company code (master data), if it could be read.
        company_code_id (str | None):
            The company code number - printed if the master data is not available.
        language (str, optional):
            The ISO language code of the document. Defaults to "EN".

    Returns:
        list[str]:
            The lines, e.g. ["Innovate Corp. US", "New York, US"].

    """

    if company_code:
        lines = [company_code.name or "", ", ".join(part for part in (company_code.city, company_code.country) if part)]
        lines = [line for line in lines if line]
        if lines:
            return lines

    return [translate("Company code {}", language).format(company_code_id)] if company_code_id else []


# end function get_sender_lines


def get_address_lines(partner: SAPBusinessPartnerResponseModel | None, label: str, number: str | None) -> list[str]:
    """Get the address lines of a business partner for the address window.

    Args:
        partner (SAPBusinessPartnerResponseModel | None):
            The business partner with its addresses, if it could be read.
        label (str):
            The role of the partner - printed with the number if there is no address, e.g. "Customer".
        number (str | None):
            The number of the partner in its role, e.g. the customer or supplier number.

    Returns:
        list[str]:
            The lines, e.g. ["Masco Technologies", "1898 Cherry St", "Philadelphia PA 19103", "US"].

    """

    name = (partner.full_name or partner.name or "").strip() if partner else ""
    address = next(iter(partner.addresses or []), None) if partner else None
    if not address:
        return [name, "{} {}".format(label, number or "")]

    # North American style ("1898 Cherry St", "Philadelphia PA 19103") or European style
    # ("Gutleutstraße 54", "60329 Frankfurt") - the region is only part of North American addresses:
    if address.country in LETTER_COUNTRIES:
        street = " ".join(part for part in (address.house_number, address.street) if part)
        city = " ".join(part for part in (address.city, address.region, address.postal_code) if part)
    else:
        street = " ".join(part for part in (address.street, address.house_number) if part)
        city = " ".join(part for part in (address.postal_code, address.city) if part)

    return [name, street, city, address.country or ""]


# end function get_address_lines


def get_partner_country(partner: SAPBusinessPartnerResponseModel | None) -> str:
    """Get the country of a business partner (of its first address).

    Args:
        partner (SAPBusinessPartnerResponseModel | None):
            The business partner with its addresses.

    Returns:
        str:
            The ISO country code or "" if unknown.

    """

    address = next(iter(partner.addresses or []), None) if partner else None

    return (address.country or "") if address else ""


# end function get_partner_country


def sort_items[T](items: list[T]) -> list[T]:
    """Sort document items by their (numeric) item number - SAP does not always return them in order.

    Args:
        items (list[T]):
            The items (with an attribute "item").

    Returns:
        list[T]:
            The sorted items.

    """

    def key(item: T) -> tuple[int, str]:
        number = str(getattr(item, "item", "") or "")
        return (int(number), number) if number.isdigit() else (10**9, number)

    return sorted(items, key=key)


# end function sort_items


def get_footer(sender: list[str], company_code_id: str | None, language: str = "EN") -> str:
    """Get the footer line: the sender and the company code.

    Args:
        sender (list[str]):
            The sender lines (see get_sender_lines()).
        company_code_id (str | None):
            The company code number.
        language (str, optional):
            The ISO language code of the document. Defaults to "EN".

    Returns:
        str:
            The footer, e.g. "Innovate Corp. US · New York, US · Company code 3000".

    """

    parts = list(sender)
    company_code_line = translate("Company code {}", language).format(company_code_id)
    if company_code_id and company_code_line not in parts:
        parts.append(company_code_line)

    return " · ".join(parts)


# end function get_footer


def get_item_number(item: str | None) -> str:
    """Get the item number as shown on SAP forms - without leading zeros, e.g. "10" for "000010".

    Args:
        item (str | None):
            The item number.

    Returns:
        str:
            The item number without leading zeros.

    """

    return (item or "").lstrip("0") or (item or "")


# end function get_item_number


def get_unit_price(amount: Decimal | float | str | None, quantity: Decimal | float | str | None) -> Decimal | None:
    """Get the unit price from the net value and the quantity of an item.

    Args:
        amount (Decimal | float | str | None):
            The net value of the item.
        quantity (Decimal | float | str | None):
            The quantity of the item.

    Returns:
        Decimal | None:
            The unit price or None if it cannot be computed.

    """

    if amount in (None, "") or quantity in (None, "") or not Decimal(str(quantity)):
        return None

    return Decimal(str(amount)) / Decimal(str(quantity))


# end function get_unit_price


def render_billing_document_pdf(
    billing_document: SAPBillingDocumentResponseModel,
    customer: SAPBusinessPartnerResponseModel | None = None,
    company_code: SAPCompanyCodeResponseModel | None = None,
    language: str | None = None,
    logo: str | bytes | None = None,
) -> bytes:
    """Render an SAP billing document (invoice, credit memo, ...) like the SAP standard form.

    Args:
        billing_document (SAPBillingDocumentResponseModel):
            The billing document with its items.
        customer (SAPBusinessPartnerResponseModel | None, optional):
            The business partner of the payer / sold-to party with its addresses (recipient).
            Defaults to None (only the customer number is printed).
        company_code (SAPCompanyCodeResponseModel | None, optional):
            The company code of the billing document (sender). Defaults to None.
        language (str | None, optional):
            The ISO language code of the document, e.g. "DE". Defaults to None: the language of the
            customer's address in SAP, else of the company code, else English.
        logo (str | bytes | None, optional):
            The path or the content of a PNG / JPEG logo for the letterhead. Defaults to None
            (company name as text).

    Returns:
        bytes:
            The PDF.

    Raises:
        RuntimeError:
            If ReportLab is not installed.

    """

    country = (company_code.country if company_code else "") or ""
    language = get_language(language, get_partner_language(customer), company_code.language if company_code else None)
    currency = billing_document.currency or ""
    customer_id = billing_document.payer or billing_document.sold_to_party or ""
    title = billing_document.category_name or "Billing Document"

    sender = get_sender_lines(company_code, billing_document.company_code, language)
    recipient = get_address_lines(customer, translate("Customer", language), customer_id)
    items = sort_items(billing_document.items or [])
    first_item = items[0] if items else None
    rows = [
        [
            get_item_number(item.item),
            item.material or "",
            item.text or "",
            format_quantity(item.quantity, country),
            item.unit or "",
            format_amount(get_unit_price(item.net_amount, item.quantity), country),
            format_amount(item.net_amount, country),
        ]
        for item in items
    ]

    data = SAPFormData(
        title=title,
        number=billing_document.billing_document_id,
        document_date=billing_document.billing_date,
        sender=sender,
        recipient=recipient,
        info=[
            ("{} number".format(title), billing_document.billing_document_id),
            ("Date", format_date(billing_document.billing_date, country)),
            ("Customer number", customer_id),
            ("Sales order", first_item.sales_document if first_item else ""),
            ("Delivery", first_item.reference_document if first_item else ""),
            ("Your reference", billing_document.customer_reference or ""),
            ("Currency", currency),
        ],
        columns=["Item", "Material", "Description", "Quantity", "Unit", "Unit price", "Net value"],
        rows=rows,
        totals=[
            ("Net value", "{} {}".format(format_amount(billing_document.total_net_amount, country), currency)),
            ("Tax", "{} {}".format(format_amount(billing_document.tax_amount, country), currency)),
            ("Total amount", "{} {}".format(format_amount(billing_document.total_gross_amount, country), currency)),
        ],
        notes=[
            ("Terms of payment", billing_document.payment_terms or ""),
            ("Payment reference", billing_document.payment_reference or billing_document.billing_document_id),
        ],
        footer=get_footer(sender, billing_document.company_code, language),
        country=country,
        language=language,
        recipient_country=get_partner_country(customer),
    )

    return render_form(data, logo=logo)


# end function render_billing_document_pdf


def render_sales_order_pdf(
    sales_order: SAPSalesOrderResponseModel,
    customer: SAPBusinessPartnerResponseModel | None = None,
    company_code: SAPCompanyCodeResponseModel | None = None,
    language: str | None = None,
    logo: str | bytes | None = None,
) -> bytes:
    """Render an SAP sales order as order confirmation (like the SAP standard form).

    Args:
        sales_order (SAPSalesOrderResponseModel):
            The sales order with its items.
        customer (SAPBusinessPartnerResponseModel | None, optional):
            The business partner of the sold-to party with its addresses (recipient). Defaults to None.
        company_code (SAPCompanyCodeResponseModel | None, optional):
            The company code of the sales organization (sender). Defaults to None.
        language (str | None, optional):
            The ISO language code of the document, e.g. "DE". Defaults to None: the language of the
            customer's address in SAP, else of the company code, else English.
        logo (str | bytes | None, optional):
            The path or the content of a PNG / JPEG logo for the letterhead. Defaults to None.

    Returns:
        bytes:
            The PDF.

    Raises:
        RuntimeError:
            If ReportLab is not installed.

    """

    country = (company_code.country if company_code else "") or ""
    language = get_language(language, get_partner_language(customer), company_code.language if company_code else None)
    currency = sales_order.currency or ""
    company_code_id = company_code.company_code if company_code else None
    sender = get_sender_lines(company_code, company_code_id, language) or [
        translate("Sales organization {}", language).format(sales_order.sales_organization or "")
    ]
    # Rejected items are not confirmed:
    items = sort_items([item for item in sales_order.items or [] if not item.rejection_reason])

    data = SAPFormData(
        title="Order Confirmation",
        number=sales_order.order_id,
        document_date=sales_order.order_date,
        sender=sender,
        recipient=get_address_lines(customer, translate("Customer", language), sales_order.sold_to_party),
        info=[
            ("Order number", sales_order.order_id),
            ("Order date", format_date(sales_order.order_date, country)),
            ("Customer number", sales_order.sold_to_party or ""),
            ("Your reference", sales_order.customer_reference or ""),
            ("Your reference date", format_date(sales_order.customer_reference_date, country)),
            ("Requested delivery", format_date(sales_order.requested_delivery_date, country)),
            ("Currency", currency),
        ],
        columns=["Item", "Material", "Description", "Quantity", "Unit", "Unit price", "Net value"],
        rows=[
            [
                get_item_number(item.item),
                item.material or "",
                item.text or "",
                format_quantity(item.quantity, country),
                item.unit or "",
                format_amount(get_unit_price(item.net_amount, item.quantity), country),
                format_amount(item.net_amount, country),
            ]
            for item in items
        ],
        totals=[("Total net value", "{} {}".format(format_amount(sales_order.total_net_amount, country), currency))],
        notes=[
            ("Terms of payment", sales_order.payment_terms or ""),
            ("", "Prices exclude taxes - they are added in the invoice."),
            ("", "Thank you for your order. We confirm it with the items and prices above."),
        ],
        footer=get_footer(sender, company_code_id, language),
        country=country,
        language=language,
        recipient_country=get_partner_country(customer),
    )

    return render_form(data, logo=logo)


# end function render_sales_order_pdf


def render_outbound_delivery_pdf(
    delivery: SAPOutboundDeliveryResponseModel,
    ship_to: SAPBusinessPartnerResponseModel | None = None,
    company_code: SAPCompanyCodeResponseModel | None = None,
    language: str | None = None,
    logo: str | bytes | None = None,
) -> bytes:
    """Render an SAP outbound delivery as delivery note (like the SAP standard form).

    Args:
        delivery (SAPOutboundDeliveryResponseModel):
            The outbound delivery with its items.
        ship_to (SAPBusinessPartnerResponseModel | None, optional):
            The business partner of the ship-to party with its addresses (recipient). Defaults to None.
        company_code (SAPCompanyCodeResponseModel | None, optional):
            The company code of the sales organization (sender). Defaults to None.
        language (str | None, optional):
            The ISO language code of the document, e.g. "DE". Defaults to None: the language of the
            ship-to party's address in SAP, else of the company code, else English.
        logo (str | bytes | None, optional):
            The path or the content of a PNG / JPEG logo for the letterhead. Defaults to None.

    Returns:
        bytes:
            The PDF.

    Raises:
        RuntimeError:
            If ReportLab is not installed.

    """

    country = (company_code.country if company_code else "") or ""
    language = get_language(language, get_partner_language(ship_to), company_code.language if company_code else None)
    company_code_id = company_code.company_code if company_code else None
    sender = get_sender_lines(company_code, company_code_id, language) or [
        translate("Shipping point {}", language).format(delivery.shipping_point or "")
    ]
    items = sort_items(
        [item for item in delivery.items or [] if item.quantity not in (None, "") and Decimal(str(item.quantity))]
    )
    sales_orders = list(dict.fromkeys(item.reference_document for item in items if item.reference_document))
    weight_unit = delivery.weight_unit or ""
    has_batches = any(item.batch for item in items)

    data = SAPFormData(
        title="Delivery Note",
        number=delivery.delivery_id,
        document_date=delivery.delivery_date,
        sender=sender,
        recipient=get_address_lines(ship_to, translate("Ship-to party", language), delivery.ship_to_party),
        info=[
            ("Delivery number", delivery.delivery_id),
            ("Delivery date", format_date(delivery.delivery_date, country)),
            ("Customer number", delivery.sold_to_party or ""),
            ("Ship-to party", delivery.ship_to_party or ""),
            ("Sales order", ", ".join(sales_orders)),
            ("Shipping point", delivery.shipping_point or ""),
            (
                "Goods issue",
                format_date(delivery.actual_goods_movement_date or delivery.planned_goods_issue_date, country),
            ),
        ],
        columns=["Item", "Material", "Description", "Quantity", "Unit"] + (["Batch"] if has_batches else []),
        rows=[
            [
                get_item_number(item.item),
                item.material or "",
                item.text or "",
                format_quantity(item.quantity, country),
                item.unit or "",
            ]
            + ([item.batch or ""] if has_batches else [])
            for item in items
        ],
        totals=[
            (label, "{} {}".format(format_quantity(value, country), weight_unit))
            for label, value in (("Net weight", delivery.net_weight), ("Gross weight", delivery.gross_weight))
            if value not in (None, "") and Decimal(str(value))
        ],
        notes=[
            ("Bill of lading", delivery.bill_of_lading or ""),
            ("", "Please check the goods on receipt and report any damage or shortfall immediately."),
        ],
        footer=get_footer(sender, company_code_id, language),
        country=country,
        language=language,
        recipient_country=get_partner_country(ship_to),
    )

    return render_form(data, logo=logo)


# end function render_outbound_delivery_pdf


def render_purchase_order_pdf(
    purchase_order: SAPPurchaseOrderResponseModel,
    supplier: SAPBusinessPartnerResponseModel | None = None,
    company_code: SAPCompanyCodeResponseModel | None = None,
    language: str | None = None,
    logo: str | bytes | None = None,
) -> bytes:
    """Render an SAP purchase order as sent to the supplier (like the SAP standard form).

    Args:
        purchase_order (SAPPurchaseOrderResponseModel):
            The purchase order with its items (and their schedule lines for the delivery dates).
        supplier (SAPBusinessPartnerResponseModel | None, optional):
            The business partner of the supplier with its addresses (recipient). Defaults to None.
        company_code (SAPCompanyCodeResponseModel | None, optional):
            The company code of the purchase order (sender). Defaults to None.
        language (str | None, optional):
            The ISO language code of the document, e.g. "DE". Defaults to None: the language of the
            supplier's address in SAP, else of the company code, else English.
        logo (str | bytes | None, optional):
            The path or the content of a PNG / JPEG logo for the letterhead. Defaults to None.

    Returns:
        bytes:
            The PDF.

    Raises:
        RuntimeError:
            If ReportLab is not installed.

    """

    country = (company_code.country if company_code else "") or ""
    language = get_language(language, get_partner_language(supplier), company_code.language if company_code else None)
    currency = purchase_order.currency or ""
    sender = get_sender_lines(company_code, purchase_order.company_code, language)
    # Deleted items are not ordered:
    items = sort_items([item for item in purchase_order.items or [] if not item.deletion_code])
    total = sum((Decimal(str(item.net_amount)) for item in items if item.net_amount not in (None, "")), Decimal(0))
    plants = list(dict.fromkeys(item.plant for item in items if item.plant))

    def delivery_date(item: object) -> str:
        dates = [line.delivery_date for line in getattr(item, "schedule_lines", None) or [] if line.delivery_date]
        return format_date(min(dates), country) if dates else ""

    data = SAPFormData(
        title="Purchase Order",
        number=purchase_order.order_id,
        document_date=purchase_order.order_date,
        sender=sender,
        recipient=get_address_lines(supplier, translate("Supplier", language), purchase_order.supplier),
        info=[
            ("Purchase order number", purchase_order.order_id),
            ("Date", format_date(purchase_order.order_date, country)),
            ("Supplier number", purchase_order.supplier or ""),
            ("Purchasing organization", purchase_order.purchasing_organization or ""),
            ("Purchasing group", purchase_order.purchasing_group or ""),
            ("Your reference", purchase_order.your_reference or ""),
            ("Currency", currency),
        ],
        columns=["Item", "Material", "Description", "Quantity", "Unit", "Delivery date", "Net price", "Net value"],
        rows=[
            [
                get_item_number(item.item),
                item.material or "",
                item.text or "",
                format_quantity(item.quantity, country),
                item.unit or "",
                delivery_date(item),
                format_amount(item.net_price, country),
                format_amount(item.net_amount, country),
            ]
            for item in items
        ],
        totals=[("Total net value", "{} {}".format(format_amount(total, country), currency))],
        notes=[
            ("Terms of payment", purchase_order.payment_terms or ""),
            ("Delivery to", ", ".join(translate("plant {}", language).format(plant) for plant in plants)),
            ("", "Please quote the purchase order number on all delivery notes and invoices."),
        ],
        footer=get_footer(sender, purchase_order.company_code, language),
        country=country,
        language=language,
        recipient_country=get_partner_country(supplier),
    )

    return render_form(data, logo=logo)


# end function render_purchase_order_pdf


def render_sales_contract_pdf(
    sales_contract: SAPSalesContractResponseModel,
    customer: SAPBusinessPartnerResponseModel | None = None,
    company_code: SAPCompanyCodeResponseModel | None = None,
    language: str | None = None,
    logo: str | bytes | None = None,
) -> bytes:
    """Render an SAP sales contract (outline agreement with a customer) as contract confirmation.

    Args:
        sales_contract (SAPSalesContractResponseModel):
            The sales contract with its items.
        customer (SAPBusinessPartnerResponseModel | None, optional):
            The business partner of the sold-to party with its addresses (recipient). Defaults to None.
        company_code (SAPCompanyCodeResponseModel | None, optional):
            The company code of the sales organization (sender). Defaults to None.
        language (str | None, optional):
            The ISO language code of the document, e.g. "DE". Defaults to None: the language of the
            customer's address in SAP, else of the company code, else English.
        logo (str | bytes | None, optional):
            The path or the content of a PNG / JPEG logo for the letterhead. Defaults to None.

    Returns:
        bytes:
            The PDF.

    Raises:
        RuntimeError:
            If ReportLab is not installed.

    """

    country = (company_code.country if company_code else "") or ""
    language = get_language(language, get_partner_language(customer), company_code.language if company_code else None)
    currency = sales_contract.currency or ""
    company_code_id = company_code.company_code if company_code else None
    sender = get_sender_lines(company_code, company_code_id, language) or [
        translate("Sales organization {}", language).format(sales_contract.sales_organization or "")
    ]
    valid_from = format_date(sales_contract.validity_start_date, country)
    valid_to = format_date(sales_contract.validity_end_date, country)

    data = SAPFormData(
        title="Contract Confirmation",
        number=sales_contract.contract_id,
        document_date=sales_contract.contract_date,
        sender=sender,
        recipient=get_address_lines(customer, translate("Customer", language), sales_contract.sold_to_party),
        info=[
            ("Contract number", sales_contract.contract_id),
            ("Contract date", format_date(sales_contract.contract_date, country)),
            ("Customer number", sales_contract.sold_to_party or ""),
            ("Valid from", valid_from),
            ("Valid to", valid_to),
            ("Your reference", sales_contract.customer_reference or ""),
            ("Currency", currency),
        ],
        columns=["Item", "Material", "Description", "Target quantity", "Unit", "Net value"],
        rows=[
            [
                get_item_number(item.item),
                item.material or "",
                item.text or "",
                format_quantity(item.quantity, country),
                item.unit or "",
                format_amount(item.net_amount if item.net_amount not in (None, "") else item.target_amount, country),
            ]
            for item in sort_items(sales_contract.items or [])
        ],
        totals=[("Total net value", "{} {}".format(format_amount(sales_contract.total_net_amount, country), currency))]
        if sales_contract.total_net_amount not in (None, "")
        else [],
        notes=[
            ("Terms of payment", sales_contract.payment_terms or ""),
            (
                "",
                translate("This contract is valid from {} to {}.", language).format(valid_from, valid_to)
                if valid_from and valid_to
                else "",
            ),
            ("", "Please quote the contract number on all orders that refer to this contract."),
        ],
        footer=get_footer(sender, company_code_id, language),
        country=country,
        language=language,
        recipient_country=get_partner_country(customer),
    )

    return render_form(data, logo=logo)


# end function render_sales_contract_pdf


def render_purchase_contract_pdf(
    purchase_contract: SAPPurchaseContractResponseModel,
    supplier: SAPBusinessPartnerResponseModel | None = None,
    company_code: SAPCompanyCodeResponseModel | None = None,
    language: str | None = None,
    logo: str | bytes | None = None,
) -> bytes:
    """Render an SAP purchase contract (outline agreement with a supplier) as sent to the supplier.

    Args:
        purchase_contract (SAPPurchaseContractResponseModel):
            The purchase contract with its items.
        supplier (SAPBusinessPartnerResponseModel | None, optional):
            The business partner of the supplier with its addresses (recipient). Defaults to None.
        company_code (SAPCompanyCodeResponseModel | None, optional):
            The company code of the purchase contract (sender). Defaults to None.
        language (str | None, optional):
            The ISO language code of the document, e.g. "DE". Defaults to None: the language of the
            supplier's address in SAP, else of the company code, else English.
        logo (str | bytes | None, optional):
            The path or the content of a PNG / JPEG logo for the letterhead. Defaults to None.

    Returns:
        bytes:
            The PDF.

    Raises:
        RuntimeError:
            If ReportLab is not installed.

    """

    country = (company_code.country if company_code else "") or ""
    language = get_language(language, get_partner_language(supplier), company_code.language if company_code else None)
    currency = purchase_contract.currency or ""
    sender = get_sender_lines(company_code, purchase_contract.company_code, language)
    valid_from = format_date(purchase_contract.validity_start_date, country)
    valid_to = format_date(purchase_contract.validity_end_date, country)

    data = SAPFormData(
        title="Purchase Contract",
        number=purchase_contract.contract_id,
        document_date=purchase_contract.creation_date,
        sender=sender,
        recipient=get_address_lines(supplier, translate("Supplier", language), purchase_contract.supplier),
        info=[
            ("Contract number", purchase_contract.contract_id),
            ("Date", format_date(purchase_contract.creation_date, country)),
            ("Supplier number", purchase_contract.supplier or ""),
            ("Purchasing organization", purchase_contract.purchasing_organization or ""),
            ("Purchasing group", purchase_contract.purchasing_group or ""),
            ("Valid from", valid_from),
            ("Valid to", valid_to),
        ],
        columns=["Item", "Material", "Description", "Target quantity", "Unit", "Net price"],
        rows=[
            [
                get_item_number(item.item),
                item.material or "",
                item.text or "",
                format_quantity(item.target_quantity, country),
                item.unit or "",
                format_amount(item.net_price, country),
            ]
            for item in sort_items([item for item in purchase_contract.items or [] if not item.deletion_code])
        ],
        totals=[("Target value", "{} {}".format(format_amount(purchase_contract.target_amount, country), currency))]
        if purchase_contract.target_amount not in (None, "") and Decimal(str(purchase_contract.target_amount))
        else [],
        notes=[
            ("Terms of payment", purchase_contract.payment_terms or ""),
            ("Currency", currency),
            (
                "",
                translate("This contract is valid from {} to {}.", language).format(valid_from, valid_to)
                if valid_from and valid_to
                else "",
            ),
            ("", "Please quote the contract number on all deliveries and invoices that refer to this contract."),
        ],
        footer=get_footer(sender, purchase_contract.company_code, language),
        country=country,
        language=language,
        recipient_country=get_partner_country(supplier),
    )

    return render_form(data, logo=logo)


# end function render_purchase_contract_pdf


def render_maintenance_order_pdf(
    maintenance_order: SAPMaintenanceOrderResponseModel,
    company_code: SAPCompanyCodeResponseModel | None = None,
    language: str | None = None,
    logo: str | bytes | None = None,
) -> bytes:
    """Render an SAP maintenance order as work order (shop paper) for the technicians or a contractor.

    Args:
        maintenance_order (SAPMaintenanceOrderResponseModel):
            The maintenance order with its operations (and their components).
        company_code (SAPCompanyCodeResponseModel | None, optional):
            The company code of the maintenance plant (sender). Defaults to None.
        language (str | None, optional):
            The ISO language code of the document, e.g. "DE". Defaults to None: the language of the
            company code in SAP, else English.
        logo (str | bytes | None, optional):
            The path or the content of a PNG / JPEG logo for the letterhead. Defaults to None.

    Returns:
        bytes:
            The PDF.

    Raises:
        RuntimeError:
            If ReportLab is not installed.

    """

    order = maintenance_order
    country = (company_code.country if company_code else "") or ""
    language = get_language(language, company_code.language if company_code else None)
    company_code_id = company_code.company_code if company_code else order.company_code
    sender = get_sender_lines(company_code, company_code_id, language) or [
        translate("Plant {}", language).format(order.planning_plant or "")
    ]
    operations = sorted(
        (operation for operation in order.operations or [] if not operation.is_marked_for_deletion),
        key=lambda operation: (operation.operation or "", operation.sub_operation or ""),
    )
    # The technical object label is the label of the equipment if the order has one:
    functional_location = order.functional_location or ("" if order.equipment else order.technical_object_label)
    technical_object = " / ".join(
        part
        for part in (
            translate("Equipment {}", language).format(order.equipment) if order.equipment else "",
            translate("Functional location {}", language).format(functional_location) if functional_location else "",
        )
        if part
    )

    data = SAPFormData(
        title="Work Order",
        number=order.order_id,
        document_date=order.creation_datetime,
        sender=sender,
        recipient=[
            translate("Work center {}", language).format(order.main_work_center or ""),
            translate("Plant {}", language).format(
                order.main_work_center_plant or order.maintenance_plant or order.planning_plant or ""
            ),
        ],
        info=[
            ("Order number", order.order_id),
            ("Order type", order.order_type or ""),
            ("Priority", order.priority or ""),
            ("Notification", order.notification or ""),
            ("Planning plant", order.planning_plant or ""),
            ("Basic start", format_date(order.basic_start_datetime, country)),
            ("Basic finish", format_date(order.basic_end_datetime, country)),
        ],
        body=[
            "<b>{}</b>".format(order.description) if order.description else "",
            "<b>{}:</b> {}".format(translate("Technical object", language), technical_object)
            if technical_object
            else "",
            "<b>{}:</b> {}".format(translate("Maintenance plan", language), order.maintenance_plan)
            if order.maintenance_plan
            else "",
        ],
        columns=["Operation", "Description", "Work center", "Control key", "Planned work", "Unit"],
        rows=[
            [
                get_item_number(operation.operation)
                + ("/{}".format(get_item_number(operation.sub_operation)) if operation.sub_operation else ""),
                operation.description or "",
                operation.work_center or "",
                operation.control_key or "",
                format_quantity(operation.planned_work, country),
                operation.planned_work_unit or "",
            ]
            for operation in operations
        ],
        tables=[
            (
                "Components",
                ["Operation", "Material", "Description", "Quantity", "Unit", "Storage location"],
                [
                    [
                        get_item_number(operation.operation),
                        component.material or "",
                        component.text or "",
                        format_quantity(component.required_quantity, country),
                        component.base_unit or "",
                        component.storage_location or "",
                    ]
                    for operation in operations
                    for component in operation.components or []
                ],
            )
        ],
        notes=[("", "Please confirm the work and the time spent per operation when the work is done.")],
        footer=get_footer(sender, company_code_id, language),
        country=country,
        language=language,
    )

    return render_form(data, logo=logo)


# end function render_maintenance_order_pdf


def render_production_order_pdf(
    production_order: SAPProductionOrderResponseModel,
    company_code: SAPCompanyCodeResponseModel | None = None,
    language: str | None = None,
    logo: str | bytes | None = None,
) -> bytes:
    """Render an SAP production order as production order papers (shop floor).

    Args:
        production_order (SAPProductionOrderResponseModel):
            The production order with its operations.
        company_code (SAPCompanyCodeResponseModel | None, optional):
            The company code of the production plant (sender). Defaults to None.
        language (str | None, optional):
            The ISO language code of the document, e.g. "DE". Defaults to None: the language of the
            company code in SAP, else English.
        logo (str | bytes | None, optional):
            The path or the content of a PNG / JPEG logo for the letterhead. Defaults to None.

    Returns:
        bytes:
            The PDF.

    Raises:
        RuntimeError:
            If ReportLab is not installed.

    """

    order = production_order
    country = (company_code.country if company_code else "") or ""
    language = get_language(language, company_code.language if company_code else None)
    company_code_id = company_code.company_code if company_code else None
    sender = get_sender_lines(company_code, company_code_id, language) or [
        translate("Plant {}", language).format(order.plant or "")
    ]
    operations = sorted(order.operations or [], key=lambda operation: operation.operation or "")

    data = SAPFormData(
        title="Production Order",
        number=order.order_id,
        document_date=order.creation_date,
        sender=sender,
        recipient=[
            translate("Production plant {}", language).format(order.plant or ""),
            translate("MRP controller {}", language).format(order.mrp_controller) if order.mrp_controller else "",
        ],
        info=[
            ("Order number", order.order_id),
            ("Order type", order.order_type or ""),
            ("Material", order.material or ""),
            ("Quantity", "{} {}".format(format_quantity(order.quantity, country), order.unit or "").strip()),
            ("Planned start", format_date(order.planned_start_date, country)),
            ("Planned finish", format_date(order.planned_end_date, country)),
            ("Sales order", order.sales_order or ""),
        ],
        body=[order.long_text or ""],
        columns=["Operation", "Description", "Work center", "Quantity", "Unit", "Start", "Finish"],
        rows=[
            [
                get_item_number(operation.operation),
                operation.text or "",
                operation.work_center or "",
                format_quantity(operation.planned_quantity, country),
                operation.unit or "",
                format_date(operation.earliest_scheduled_start_date, country),
                format_date(operation.earliest_scheduled_end_date, country),
            ]
            for operation in operations
        ],
        notes=[
            ("Storage location", order.storage_location or ""),
            ("", "Please confirm the yield and the activities per operation."),
        ],
        footer=get_footer(sender, company_code_id, language),
        country=country,
        language=language,
    )

    return render_form(data, logo=logo)


# end function render_production_order_pdf


def get_goods_movement_title(goods_movement: SAPGoodsMovementResponseModel) -> str:
    """Get the title of a goods movement slip from the movement type of its items.

    Args:
        goods_movement (SAPGoodsMovementResponseModel):
            The goods movement (material document) with its items.

    Returns:
        str:
            "Goods Receipt Slip" (movement types 1xx / 5xx), "Goods Issue Slip" (2xx / 6xx),
            "Transfer Posting Slip" (3xx / 4xx) or "Material Document".

    """

    movement_type = next((item.movement_type for item in goods_movement.items or [] if item.movement_type), "")
    titles = {
        "1": "Goods Receipt Slip",
        "5": "Goods Receipt Slip",
        "2": "Goods Issue Slip",
        "6": "Goods Issue Slip",
        "3": "Transfer Posting Slip",
        "4": "Transfer Posting Slip",
    }

    return titles.get(movement_type[:1], "Material Document")


# end function get_goods_movement_title


def render_goods_movement_pdf(
    goods_movement: SAPGoodsMovementResponseModel,
    company_code: SAPCompanyCodeResponseModel | None = None,
    language: str | None = None,
    logo: str | bytes | None = None,
) -> bytes:
    """Render an SAP goods movement (material document) as goods receipt / issue slip.

    Args:
        goods_movement (SAPGoodsMovementResponseModel):
            The goods movement with its items.
        company_code (SAPCompanyCodeResponseModel | None, optional):
            The company code of the plant (sender). Defaults to None.
        language (str | None, optional):
            The ISO language code of the document, e.g. "DE". Defaults to None: the language of the
            company code in SAP, else English.
        logo (str | bytes | None, optional):
            The path or the content of a PNG / JPEG logo for the letterhead. Defaults to None.

    Returns:
        bytes:
            The PDF.

    Raises:
        RuntimeError:
            If ReportLab is not installed.

    """

    movement = goods_movement
    country = (company_code.country if company_code else "") or ""
    language = get_language(language, company_code.language if company_code else None)
    company_code_id = company_code.company_code if company_code else None
    items = sort_items(movement.items or [])
    first_item = items[0] if items else None
    sender = get_sender_lines(company_code, company_code_id, language) or [
        translate("Plant {}", language).format(first_item.plant if first_item else "")
    ]
    has_batches = any(item.batch for item in items)
    purchase_orders = list(dict.fromkeys(item.purchase_order for item in items if item.purchase_order))
    orders = list(dict.fromkeys(item.manufacturing_order for item in items if item.manufacturing_order))
    suppliers = list(dict.fromkeys(item.supplier for item in items if item.supplier))

    data = SAPFormData(
        title=get_goods_movement_title(movement),
        number="{}/{}".format(movement.document, movement.document_year),
        document_date=movement.posting_date,
        sender=sender,
        recipient=[
            translate("Plant {}", language).format(first_item.plant or "") if first_item else "",
            translate("Storage location {}", language).format(first_item.storage_location)
            if first_item and first_item.storage_location
            else "",
        ],
        info=[
            ("Material document", movement.document),
            ("Year", movement.document_year),
            ("Posting date", format_date(movement.posting_date, country)),
            ("Document date", format_date(movement.document_date, country)),
            ("Delivery note", movement.reference_document or ""),
            ("Purchase order", ", ".join(purchase_orders)),
            ("Order", ", ".join(orders)),
        ],
        body=[movement.header_text or ""],
        columns=["Item", "Material", "Description", "Quantity", "Unit", "Movement type", "Storage location"]
        + (["Batch"] if has_batches else []),
        rows=[
            [
                get_item_number(item.item),
                item.material or "",
                item.text or "",
                format_quantity(item.quantity, country),
                item.unit or "",
                item.movement_type or "",
                item.storage_location or "",
            ]
            + ([item.batch or ""] if has_batches else [])
            for item in items
        ],
        notes=[
            ("Supplier", ", ".join(suppliers)),
            ("Created by", movement.created_by_user or ""),
        ],
        footer=get_footer(sender, company_code_id, language),
        country=country,
        language=language,
    )

    return render_form(data, logo=logo)


# end function render_goods_movement_pdf
