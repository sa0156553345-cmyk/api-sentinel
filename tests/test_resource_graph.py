import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
import api_sentinel as s  # noqa: E402


DOC = {
    "openapi": "3.0.3",
    "paths": {
        "/users/{user_id}/orders": {
            "get": {"operationId": "listUserOrders"},
        },
        "/orders/{id}": {
            "get": {
                "operationId": "getOrder",
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Order"}
                            }
                        }
                    }
                },
            }
        },
        "/orders": {
            "post": {"operationId": "createOrder"},
        },
    },
    "components": {
        "schemas": {
            "Order": {
                "properties": {
                    "id": {"type": "integer"},
                    "user_id": {"type": "integer"},
                    "item": {"type": "string"},
                }
            }
        }
    },
}


def test_infers_order_resource_with_owner_field():
    graph = s.infer_resource_graph(DOC)
    assert "Order" in graph["resources"]
    assert "user_id" in graph["resources"]["Order"]["owner_fields"]
    # the Order's own primary key must NOT be treated as an ownership field
    assert "id" not in graph["resources"]["Order"]["owner_fields"]


def test_infers_user_owns_order_relationship():
    graph = s.infer_resource_graph(DOC)
    assert any(
        e["from"] == "User" and e["to"] == "Order" and e["via"] == "user_id"
        for e in graph["relationships"]
    )


def test_format_graph_runs_without_error():
    graph = s.infer_resource_graph(DOC)
    text = s.format_graph(graph)
    assert "Order" in text
    assert isinstance(text, str) and len(text) > 0
