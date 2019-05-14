class Fork():
    def __init__(self):
        self.POW_FORK = 1200000
        self.POW_FORK_TESTNET = 894170
        self.FORK_AHEAD = 5
        self.versions_remove = ['mainnet0019', 'mainnet0018', 'mainnet0017']

    def limit_version(self, node):
        for allowed_version in node.version_allow:
            if allowed_version in self.versions_remove:
                node.logger.app_log.warning(f"Beginning to reject old protocol versions - block {node.last_block}")
                node.version_allow.remove(allowed_version)

