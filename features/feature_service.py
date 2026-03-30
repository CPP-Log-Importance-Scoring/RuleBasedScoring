import logging
from parsing.schema import LogRecord
logger= logging.getLogger(__name__)
#mapping that converts log levels to numbers
SEVERITY_MAP: dict[str,float]={
    "INFO": 1.0,
    "WARN": 2.0,
    "ERROR": 3.0,
    "CRITICAL":4.0,
}

EVENT_TYPE_SCORE_TABLE: dict[tuple[str,str],float]={
    #OSPF routing failures
    ("OSPF", "NEIGHBOR_DOWN"):        4.0,
    ("OSPF", "STATE_CHANGE"):         2.5,
    ("OSPF", "*"):                    2.5,
    #SECURITY
    ("SECURITY", "PORT_SCAN"):        4.0,
    ("SECURITY", "MAC_BLOCKED"):      4.0,
    ("SECURITY", "GENERIC"):          3.0,
    ("SECURITY", "*"):                3.0,
    #SNMP(Simple Network Management Protocol)
     ("SNMP", "AUTH_FAILURE"):         3.0,
    ("SNMP", "GENERIC"):              1.0,
    ("SNMP", "*"):                    1.0,
    #Port
    ("PORT", "PORT_DOWN"):            3.0,
    ("PORT", "PORT_UP"):              1.0,
    ("PORT", "STATE_CHANGE"):         1.5,
    ("PORT", "*"):                    1.5,
    #DHCP-Snoop
     ("DHCP_SNOOP", "PACKET_DROPPED"): 2.0,
    ("DHCP_SNOOP", "*"):              2.0,
    #VLAN
     ("VLAN", "VLAN_ADDED"):           1.0,
    ("VLAN", "VLAN_REMOVED"):         1.5,
    ("VLAN", "CHANGE"):               1.0,
    ("VLAN", "*"):                    1.0,
    #IDM
    ("IDM", "ACL_ERROR"):             2.5,
    ("IDM", "GENERIC"):               1.0,
    ("IDM", "*"):                     1.0,
    #CONFIG
    ("CONFIG", "CONFIG_CHANGE"):      1.0,
    ("CONFIG", "GENERIC"):            1.0,
    ("CONFIG", "*"):                  1.0,
    #SYSLOG
    ("SYSLOG", "LOGGING_STARTED"):    0.5,
    ("SYSLOG", "*"):                  0.5,
}

def get_severity_score(log_level: str) -> float:
    #Maps loglevel to numeric severity score
    score= SEVERITY_MAP.get(log_level.upper() if log_level else "INFO",1.0)
    logger.debug("severity_score(%s)= %.1f",log_level,score)
    return score
#Map (event_type,event_action) to event type score
def get_event_type_score(event_type: str, event_action: str)-> float:
    et= event_type.upper() if event_type else "*"
    ea= event_action.upper() if event_action else "*"

    score= EVENT_TYPE_SCORE_TABLE.get((et,ea))
    if score is not None:
        logger.debug("event_type_score(%s,%s) = %.1f[exact]",et,ea,score)
        return score
    
    score = EVENT_TYPE_SCORE_TABLE.get((et, "*"))
    if score is not None:
        logger.debug("event_type_score(%s, %s) = %.1f [wildcard]", et, ea, score)
        return score
 
    logger.debug("event_type_score(%s, %s) = 1.0 [default]", et, ea)
    return 1.0

def compute_features(record: LogRecord)-> LogRecord:
    record.severity_score= get_severity_score(record.log_level)
    record.event_type_score=get_event_type_score(record.event_type, record.event_action)

    logger.info(
        "features: severity_score=%.1f event_type_score=%.1f "
        "host=%s  service=%s  %s/%s",
        record.severity_score, record.event_type_score,
        record.host, record.service,
        record.event_type, record.event_action,
    )
    return record

def compute_features_batch(records:list[LogRecord])-> list[LogRecord]:
    for record in records:
        compute_features(record)
    return records;


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
 
    cases = [
        ("CRITICAL", "OSPF",     "NEIGHBOR_DOWN", 4.0, 4.0),
        ("ERROR",    "SNMP",     "AUTH_FAILURE",  3.0, 3.0),
        ("WARN",     "PORT",     "PORT_DOWN",     2.0, 3.0),
        ("INFO",     "PORT",     "PORT_UP",       1.0, 1.0),
        ("INFO",     "VLAN",     "VLAN_ADDED",    1.0, 1.0),
        ("INFO",     "CONFIG",   "CONFIG_CHANGE", 1.0, 1.0),
        ("INFO",     "SYSLOG",   "LOGGING_STARTED", 1.0, 0.5),
        ("INFO",     "UNKNOWN",  "WHATEVER",      1.0, 1.0),  
    ]
 
    print(f"{'log_level':<10} {'event_type':<12} {'action':<18} "
          f"{'sev':>5} {'etype':>6}  status")
    print("─" * 65)
    all_pass = True
    for log_level, et, ea, exp_sev, exp_etype in cases:
        r = LogRecord(log_level=log_level, event_type=et, event_action=ea,
                      timestamp="", raw_line="", host="", service="", message="")
        compute_features(r)
        ok = (r.severity_score == exp_sev and r.event_type_score == exp_etype)
        status = "PASS" if ok else f"FAIL (got sev={r.severity_score} etype={r.event_type_score})"
        print(f"{log_level:<10} {et:<12} {ea:<18} {r.severity_score:>5.1f} "
              f"{r.event_type_score:>6.1f}  {status}")
        if not ok:
            all_pass = False
 
    print()
    print("All tests PASS" if all_pass else "SOME TESTS FAILED")

