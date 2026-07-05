from enum import StrEnum

# https://github.com/wazuh/wazuh/blob/v4.14.5/src/headers/mq_op.h
class WazuhMqMessageEnum(StrEnum):
    LOCALFILE_MQ = "1"
    SYSLOG_MQ = "2"
    HOSTINFO_MQ = "3"
    SECURE_MQ = "4"
    DBSYNC_MQ = "5"
    SYSCHECK_MQ = "8"
    ROOTCHECK_MQ = "9"
    SYSCOLLECTOR_MQ = "d"
    CISCAT_MQ = "e"
    WIN_EVT_MQ = "f"
    SCA_MQ = "p"
    UPGRADE_MQ = "u"


# https://github.com/wazuh/wazuh/blob/v4.14.5/src/headers/rc.h
class WazuhRcMessageEnum(StrEnum):
    START_HEADER = "#!-"
    STARTUP = "agent startup "  # first agent request
    SHUTDOWN = "agent shutdown "
    ACK = "agent ack "  # first server response
    REQUEST = "req "
    ERROR = "err "
    RESTART = "restart"
    FORCE_RECONNECT = "force_reconnect"
    GETCONFIG = "getconfig"
    EXECD = "execd "
    FILE_UPDATE = "up file "
    FILE_CLOSE = "close file "
    SYSCHECK = "syscheck "
    SK_RESTART = "syscheck restart"
    SK_DB_COMPLETED = "syscheck-db-completed"
    FIM_FILE = "fim_file "
    FIM_REGISTRY = "fim_registry "
    FIM_REGISTRY_KEY = "fim_registry_key "
    FIM_REGISTRY_VALUE = "fim_registry_value "
    FIM_DB_START_FIRST_SCAN = "fim-db-start-first-scan"
    FIM_DB_END_FIRST_SCAN = "fim-db-end-first-scan"
    FIM_DB_START_SCAN = "fim-db-start-scan"
    FIM_DB_END_SCAN = "fim-db-end-scan"
    SCA_DUMP = "sca-dump"
    SYSCOLLECTOR = "syscollector_"
    INVALID_VERSION_RESPONSE = "Agent version must be lower or equal to manager version"
    INVALID_VERSION = "Incompatible version"
    RETRIEVE_VERSION = "Couldn't retrieve version"


# Pre-encoded control-message bytes
class WazuhRcEventBytes:
    START_HEADER = WazuhRcMessageEnum.START_HEADER.encode()
    SHUTDOWN = f"{WazuhRcMessageEnum.START_HEADER}{WazuhRcMessageEnum.SHUTDOWN}".encode()
    STARTUP = f"{WazuhRcMessageEnum.START_HEADER}{WazuhRcMessageEnum.STARTUP}".encode()
    ACK = f"{WazuhRcMessageEnum.START_HEADER}{WazuhRcMessageEnum.ACK}".encode()

