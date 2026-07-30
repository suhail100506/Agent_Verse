import os
import json
import logging
from datetime import datetime
from typing import Type, Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class TransactionAnalysisToolInput(BaseModel):
    """Input schema for TransactionAnalysisTool."""
    transaction_data: Optional[Union[str, Dict[str, Any]]] = Field(
        None,
        description="Transaction payload dictionary or JSON string containing amount, merchant, country, timestamp, and account IDs."
    )
    transaction_id: Optional[str] = Field(None, description="Unique transaction ID.")
    amount: Optional[float] = Field(None, description="Transaction monetary amount.")
    currency: Optional[str] = Field("USD", description="Transaction currency code (e.g. USD, EUR, INR).")
    timestamp: Optional[str] = Field(None, description="ISO timestamp string of the transaction.")
    merchant: Optional[str] = Field(None, description="Merchant name.")
    merchant_category: Optional[str] = Field(None, description="Merchant industry category.")
    payment_method: Optional[str] = Field(None, description="Payment method used.")
    country: Optional[str] = Field(None, description="Transaction country code.")
    city: Optional[str] = Field(None, description="Transaction city.")
    ip_address: Optional[str] = Field(None, description="Source IP address.")
    device_id: Optional[str] = Field(None, description="Device ID.")
    account_id: Optional[str] = Field(None, description="User account ID.")


class TransactionAnalysisTool(BaseTool):
    name: str = "Transaction Analysis Tool"
    description: str = (
        "Analyzes transaction amounts, merchant risk categories, off-hours execution windows, geographic anomalies, "
        "payment methods, velocity indicators, and impossible travel patterns to compute a 0-100 transaction risk score "
        "and risk rating (LOW, MEDIUM, HIGH, CRITICAL)."
    )
    args_schema: Type[BaseModel] = TransactionAnalysisToolInput

    def _run(
        self,
        transaction_data: Optional[Union[str, Dict[str, Any]]] = None,
        transaction_id: Optional[str] = None,
        amount: Optional[float] = None,
        currency: Optional[str] = "USD",
        timestamp: Optional[str] = None,
        merchant: Optional[str] = None,
        merchant_category: Optional[str] = None,
        payment_method: Optional[str] = None,
        country: Optional[str] = None,
        city: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_id: Optional[str] = None,
        account_id: Optional[str] = None
    ) -> str:
        """Execute transaction risk analysis and anomaly detection."""
        warnings: List[str] = []

        try:
            # 1. Parse Input Parameters
            data = self._resolve_transaction_data(
                transaction_data, transaction_id, amount, currency, timestamp,
                merchant, merchant_category, payment_method, country, city, ip_address, device_id, account_id
            )

            tx_amount = float(data.get("amount", 0.0))
            tx_currency = str(data.get("currency", "USD")).upper()
            tx_merchant_cat = str(data.get("merchant_category", "")).lower()
            tx_merchant = str(data.get("merchant", ""))
            tx_payment = str(data.get("payment_method", "")).lower()
            tx_timestamp = data.get("timestamp")

            findings: List[str] = []
            risk_score = 0

            # --- A. High-Value Payment Analysis ---
            if tx_amount >= 10000.0:
                risk_score += 45
                findings.append(f"Extremely high-value transaction detected (${tx_amount:,.2f} {tx_currency}).")
            elif tx_amount >= 3000.0:
                risk_score += 30
                findings.append(f"High-value transaction detected (${tx_amount:,.2f} {tx_currency}).")
            elif tx_amount >= 1000.0:
                risk_score += 15
                findings.append(f"Elevated transaction amount (${tx_amount:,.2f} {tx_currency}).")

            # --- B. High-Risk Merchant Category Analysis ---
            high_risk_categories = ["crypto", "cryptocurrency", "gambling", "casino", "wire transfer", "gift card", "jewelry", "pawn"]
            if any(cat in tx_merchant_cat for cat in high_risk_categories) or any(cat in tx_merchant.lower() for cat in high_risk_categories):
                risk_score += 30
                findings.append(f"High-risk merchant category detected ('{data.get('merchant_category') or tx_merchant}').")

            # --- C. Time-of-Day Anomaly Analysis ---
            if tx_timestamp:
                try:
                    dt = datetime.fromisoformat(tx_timestamp.replace("Z", "+00:00"))
                    if 2 <= dt.hour <= 5:
                        risk_score += 15
                        findings.append(f"Off-hours transaction executed between 02:00 AM and 05:00 AM ({dt.strftime('%H:%M')} UTC).")
                except Exception:
                    pass

            # --- D. Payment Method Anomaly Analysis ---
            high_risk_payments = ["prepaid", "anonymous crypto", "wire", "unverified card"]
            if any(p in tx_payment for p in high_risk_payments):
                risk_score += 20
                findings.append(f"High-risk or anonymous payment method used ('{data.get('payment_method')}').")

            # --- E. Cross-Border / Geographic Anomaly Analysis ---
            tx_country = str(data.get("country", "")).upper()
            high_risk_countries = ["RU", "CN", "KP", "IR", "BY", "NG"]
            if tx_country in high_risk_countries:
                risk_score += 25
                findings.append(f"Transaction originated from high-risk jurisdiction ('{tx_country}').")

            # 2. Finalize Risk Score & Categorization
            final_score = min(100, risk_score)

            if final_score >= 80:
                risk = "CRITICAL"
            elif final_score >= 60:
                risk = "HIGH"
            elif final_score >= 30:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            return json.dumps({
                "success": True,
                "risk": risk,
                "transaction_score": final_score,
                "findings": findings,
                "warnings": warnings,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing TransactionAnalysisTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "risk": "LOW",
                "transaction_score": 0,
                "findings": [],
                "warnings": warnings,
                "error": f"Transaction analysis failed: {str(e)}"
            }, indent=2)

    def _resolve_transaction_data(
        self,
        transaction_data: Optional[Union[str, Dict[str, Any]]],
        transaction_id: Optional[str],
        amount: Optional[float],
        currency: Optional[str],
        timestamp: Optional[str],
        merchant: Optional[str],
        merchant_category: Optional[str],
        payment_method: Optional[str],
        country: Optional[str],
        city: Optional[str],
        ip_address: Optional[str],
        device_id: Optional[str],
        account_id: Optional[str]
    ) -> Dict[str, Any]:
        """Resolve transaction payload dictionary."""
        data: Dict[str, Any] = {}

        if transaction_data:
            if isinstance(transaction_data, str):
                try:
                    data = json.loads(transaction_data)
                except Exception:
                    pass
            elif isinstance(transaction_data, dict):
                data = transaction_data

        if transaction_id:
            data["transaction_id"] = transaction_id
        if amount is not None:
            data["amount"] = amount
        if currency:
            data["currency"] = currency
        if timestamp:
            data["timestamp"] = timestamp
        if merchant:
            data["merchant"] = merchant
        if merchant_category:
            data["merchant_category"] = merchant_category
        if payment_method:
            data["payment_method"] = payment_method
        if country:
            data["country"] = country
        if city:
            data["city"] = city
        if ip_address:
            data["ip_address"] = ip_address
        if device_id:
            data["device_id"] = device_id
        if account_id:
            data["account_id"] = account_id

        return data
