import json
from pydantic import BaseModel

__all__ = ["compare_via_json", "compare_model_json"]


def compare_via_json(x: dict | list, y: dict | list) -> bool:
    return json.dumps(x, sort_keys=True) == json.dumps(y, sort_keys=True)


def compare_model_json(x: BaseModel, y: BaseModel, **kwargs) -> bool:
    return compare_via_json(x.model_dump(mode="json", **kwargs), y.model_dump(mode="json", **kwargs))
