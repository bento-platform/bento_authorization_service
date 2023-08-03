import json
from pydantic import BaseModel

__all__ = ["json_model_dump_kwargs"]


def json_model_dump_kwargs(x: BaseModel, **kwargs):
    return json.dumps(x.model_dump(mode="json"), **kwargs)
