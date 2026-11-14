import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger("reconforge.iot")


class IoTEventType(str, Enum):
    possible_fall = "possible_fall"
    high_temperature = "high_temperature"
    abnormal_heart_rate = "abnormal_heart_rate"
    sos = "sos"


class IoTSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IoTEventCreate(BaseModel):
    device_id: str
    event: IoTEventType
    severity: IoTSeverity
    timestamp: datetime
    data: Dict[str, Any]


router = APIRouter(prefix="/iot", tags=["IoT"])


@router.post("/events")
async def receive_iot_event(event: IoTEventCreate):
    logger.info("Received IoT event: %s", event.model_dump(mode="json"))
    return {
        "message": "IoT event received",
        "device_id": event.device_id,
        "event": event.event,
        "severity": event.severity,
        "received": True,
    }
