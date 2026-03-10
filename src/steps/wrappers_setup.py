class NodeStub:
    def send_message(self, message, timeout_s=20.0):
        self.message = message
        self.timeout_s = timeout_s
        return Ok(1)

    def get_available_node_info_ids(self, timeout_s=20.0):
        self.timeout_s = timeout_s
        return Ok(2)

    def get_node_info(self, node_info_id, timeout_s=20.0):
        self.node_info_id = node_info_id
        self.timeout_s = timeout_s
        return Ok(3)

    def get_available_configs(self, timeout_s=20.0):
        self.timeout_s = timeout_s
        return Ok(4)
