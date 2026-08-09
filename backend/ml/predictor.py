import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

class MLPredictor:
    def __init__(self, model_dir: str = "models"):
        self.enabled = False
        logger.info("[ML Predictor] ML disabled for local standalone mode. Returning defaults.")

    def reload_models(self):
        pass

    def predict_flow(self, flow_features: Dict[str, Any]) -> Tuple[bool, float, str]:
        return False, 0.0, "normal"

predictor = MLPredictor()
