from dataclasses import dataclass
from typing import Type, Any

@dataclass
class Parameters:
    name: str
    type: Type
    required: bool
    help: str = ""
    default: Any | None = None
    attr_name: str | None = None 
