class Fork():
    def __init__(self):
        self.POW_FORK = 854660
        self.FORK_AHEAD = 5
        self.FORK_DIFF = 108.9

    def limit_version(self, node):
        if 'mainnet0018' in node.version_allow:
            node.logger.app_log.warning(f"Beginning to reject mainnet0018 - block {node.last_block}")
            node.version_allow.remove('mainnet0018')

class Fork2():
    def __init__(self):
        self.POW_FORK = 1200000
        self.FORK_AHEAD = 5

    def limit_version(self, node):
        if 'mainnet0019' in node.version_allow:
            node.logger.app_log.warning(f"Beginning to reject mainnet0019 - block {node.last_block}")
            node.version_allow.remove('mainnet0019')
