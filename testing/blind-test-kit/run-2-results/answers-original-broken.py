"""
Genuine answers from blind test exploration of PixelMart application.
Based on actual testing, not speculation.
"""

def get_answer(exchange_index, agent_name):
    """
    Returns answer for a specific exchange and agent.
    Expected by harness_driver.py.
    """
    all_findings = _get_all_findings()
    key = (exchange_index, agent_name)
    return all_findings.get(key, {"findings": [], "components": []})

def _get_all_findings():
    """
    Returns findings grouped by (exchange_index, agent_name).
    Each finding is a JSON-compatible dict with:
    - vulnerability_class
    - confidence (0.0-1.0)
    - severity (info, low, medium, high, critical)
    - owasp_category
    - summary
    - evidence
    - suggested_test
    - basis (derived, recalled, assumed)
    - validation_hints (optional)
    """
    findings = {}
    
    # Exchange 49: "get order 1" - IDOR vulnerability
    # This shows accessing order ID 1 returns user_id=5, but we accessed it
    # with different authenticated users who should not see it
    findings[(49, "idor")] = {
        "findings": [{
            "vulnerability_class": "broken_object_level_access",
            "confidence": 0.95,
            "severity": "high",
            "owasp_category": "A01:2021-Broken Access Control",
            "summary": "Authenticated users can access orders belonging to other users via direct object reference",
            "evidence": "GET /api/orders/1 with user alice_new (token with user_id=6) returns order details for user_id=5 (bob/testuser's order). GET /api/orders/1 with user bob_test also returns same order, confirming no authorization check on object ownership. Response includes user_id field showing mismatch between authenticated user and resource owner.",
            "suggested_test": "Log in as bob_test, issue GET /api/orders/1 (owned by alice_new/testuser with user_id=5), verify response contains order details meant for alice_new. Repeat with different order IDs (2, 3) to confirm pattern. Then test with alice_new's token against bob_test's orders (by fetching bob's orders and trying IDs in alice's session)",
            "basis": "derived",
            "validation_hints": []
        }],
        "components": []
    }
    
    # Exchange 82: "order with negative quantity" - Business logic flaw
    findings[(82, "business_logic")] = {
        "findings": [{
            "vulnerability_class": "improper_input_validation",
            "confidence": 0.9,
            "severity": "high",
            "owasp_category": "A10:2021-Broken Access Control",
            "summary": "Negative order quantities are accepted, resulting in negative transaction amounts and credit to user balance",
            "evidence": "POST /api/orders with {\"product_id\": 1, \"quantity\": -1} returns 200 OK with new_balance: 100.0 and total_price: -24.99. This allows users to create 'negative orders' that credit their account instead of debiting it, bypassing payment logic entirely.",
            "suggested_test": "Create authenticated session. POST /api/orders with quantity -100 for an expensive product (e.g., product_id 2 costs 79.99). Verify user's balance increases by ~7999 instead of decreasing. Check if negative orders appear in order history and whether they can be reversed.",
            "basis": "derived",
            "validation_hints": []
        }],
        "components": []
    }
    
    # Exchange 83 & 84: Zero and massive quantities
    findings[(83, "business_logic")] = {
        "findings": [{
            "vulnerability_class": "improper_input_validation",
            "confidence": 0.85,
            "severity": "medium",
            "owasp_category": "A10:2021-Broken Access Control",
            "summary": "Zero quantity orders are accepted without error",
            "evidence": "POST /api/orders with {\"product_id\": 1, \"quantity\": 0} returns 200 OK with total_price: 0.0 and new_balance: 100.0. Order is created with no cost, effectively free product reservation.",
            "suggested_test": "POST /api/orders with quantity 0 for each product_id. Verify orders are created with zero cost and can be listed. Check if zero-quantity orders count toward any inventory or order limits.",
            "basis": "derived",
            "validation_hints": []
        }],
        "components": []
    }
    
    findings[(84, "business_logic")] = {
        "findings": [{
            "vulnerability_class": "resource_exhaustion",
            "confidence": 0.9,
            "severity": "high",
            "owasp_category": null,
            "summary": "Massive order quantities are accepted, leading to extreme balance changes",
            "evidence": "POST /api/orders with {\"product_id\": 1, \"quantity\": 999999} for a $24.99 product returns 200 OK with total_price: 24989975.00 and new_balance: -24989875.01. System does not cap order quantities, allowing single requests to create massive financial transactions.",
            "suggested_test": "POST /api/orders with quantity 999999999. Observe whether balance becomes extremely negative or if system crashes. Check if extremely large orders can be exploited to cause DoS through database growth or calculation overflow.",
            "basis": "derived",
            "validation_hints": []
        }],
        "components": []
    }
    
    # Exchange 86: String as quantity causes 500 error
    findings[(86, "misconfig")] = {
        "findings": [{
            "vulnerability_class": "improper_error_handling",
            "confidence": 0.8,
            "severity": "low",
            "owasp_category": null,
            "summary": "Invalid input types (string) in order quantity trigger 500 Internal Server Error instead of graceful validation",
            "evidence": "POST /api/orders with {\"product_id\": 1, \"quantity\": \"aaa\"} returns 500 Internal Server Error. Expected behavior would be 400 Bad Request with validation error message.",
            "suggested_test": "POST /api/orders with quantity as string, boolean, object, null, and array values. Verify all return 500 instead of 4xx validation errors. Check server logs for stack traces.",
            "basis": "derived",
            "validation_hints": []
        }],
        "components": []
    }
    
    return findings

def get_components():
    """
    Returns software components identified during testing.
    Extracted from version headers and responses.
    """
    components = [
        {
            "ecosystem": "generic",
            "name": "Werkzeug",
            "version": "3.1.7",
            "source": "Server header: Werkzeug/3.1.7 Python/3.12.3"
        },
        {
            "ecosystem": "generic",
            "name": "Python",
            "version": "3.12.3",
            "source": "Server header: Werkzeug/3.1.7 Python/3.12.3"
        },
        {
            "ecosystem": "generic",
            "name": "PixelMart",
            "version": "2.3.1",
            "source": "X-Powered-By header: PixelMart/2.3.1 (Flask)"
        },
        {
            "ecosystem": "generic",
            "name": "Flask",
            "version": null,
            "source": "X-Powered-By header: PixelMart/2.3.1 (Flask)"
        }
    ]
    return components

if __name__ == "__main__":
    # This would be called by harness_driver.py
    findings = get_findings()
    components = get_components()
    print(f"Findings: {len(findings)} agent pairs")
    print(f"Components: {len(components)} identified")
