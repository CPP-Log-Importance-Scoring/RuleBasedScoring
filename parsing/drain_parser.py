from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig


class DrainParser:
    def __init__(self):
        config = TemplateMinerConfig()

        # 🔥 Manual config (since load_default() not available)
        config.drain_sim_th = 0.4
        config.drain_depth = 4

        self.miner = TemplateMiner(config=config)

    def parse(self, message: str):
        """
        Parse log message using Drain and return:
        (cluster_id, template)
        """

        result = self.miner.add_log_message(message)

        # 🔥 Handle version differences safely
        cluster_id = result.get("cluster_id")

        # Some versions use "template_mined", others "template"
        template = result.get("template_mined") or result.get("template")

        # Fallback safety
        if template is None:
            template = message

        return cluster_id, template


# Singleton instance
drain_parser = DrainParser()