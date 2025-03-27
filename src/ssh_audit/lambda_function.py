#!/usr/bin/env python3

import traceback
from typing import Any, Dict

from ssh_audit import exitcodes
from ssh_audit.auditconf import AuditConf
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.ssh_audit import audit


def lambda_handler(event: Dict[str, Any], _context: Dict[str, Any]) -> Dict[str, Any]:
    out = OutputBuffer()
    aconf = AuditConf()

    aconf.batch = event["audit_conf"].get("batch", aconf.batch)
    aconf.client_audit = event["audit_conf"].get("client_audit", aconf.client_audit)
    aconf.colors = event["audit_conf"].get("colors", aconf.colors)
    aconf.conn_rate_test_enabled = event["audit_conf"].get(
        "conn_rate_test_enabled", aconf.conn_rate_test_enabled
    )
    aconf.conn_rate_test_target_rate = event["audit_conf"].get(
        "conn_rate_test_target_rate", aconf.conn_rate_test_target_rate
    )
    aconf.conn_rate_test_threads = event["audit_conf"].get(
        "conn_rate_test_threads", aconf.conn_rate_test_threads
    )
    aconf.debug = event["audit_conf"].get("debug", aconf.debug)
    aconf.dheat = event["audit_conf"].get("dheat", aconf.dheat)
    aconf.dheat_concurrent_connections = event["audit_conf"].get(
        "dheat_concurrent_connections", aconf.dheat_concurrent_connections
    )
    aconf.dheat_e_length = event["audit_conf"].get(
        "dheat_e_length", aconf.dheat_e_length
    )
    aconf.dheat_target_alg = event["audit_conf"].get(
        "dheat_target_alg", aconf.dheat_target_alg
    )
    aconf.gex_test = event["audit_conf"].get("gex_test", aconf.gex_test)
    aconf.host = event["audit_conf"].get("host", aconf.host)
    aconf.ip_version_preference = event["audit_conf"].get(
        "ip_version_preference", aconf.ip_version_preference
    )
    aconf.ipv4 = event["audit_conf"].get("ipv4", aconf.ipv4)
    aconf.ipv6 = event["audit_conf"].get("ipv6", aconf.ipv6)
    aconf.json = event["audit_conf"].get("json", aconf.json)
    aconf.json_print_indent = event["audit_conf"].get(
        "json_print_indent", aconf.json_print_indent
    )
    aconf.level = event["audit_conf"].get("level", aconf.level)
    aconf.list_policies = event["audit_conf"].get("list_policies", aconf.list_policies)
    aconf.lookup = event["audit_conf"].get("lookup", aconf.lookup)
    aconf.make_policy = event["audit_conf"].get("make_policy", aconf.make_policy)
    aconf.manual = event["audit_conf"].get("manual", aconf.manual)
    aconf.policy = event["audit_conf"].get("policy", aconf.policy)
    aconf.policy_file = event["audit_conf"].get("policy_file", aconf.policy_file)
    aconf.port = event["audit_conf"].get("port", aconf.port)
    aconf.skip_rate_test = event["audit_conf"].get(
        "skip_rate_test", aconf.skip_rate_test
    )
    aconf.ssh1 = event["audit_conf"].get("ssh1", aconf.ssh1)
    aconf.ssh2 = event["audit_conf"].get("ssh2", aconf.ssh2)
    aconf.target_file = event["audit_conf"].get("target_file", aconf.target_file)
    aconf.target_list = event["audit_conf"].get("target_list", aconf.target_list)
    aconf.threads = event["audit_conf"].get("threads", aconf.threads)
    aconf.timeout = event["audit_conf"].get("timeout", aconf.timeout)
    aconf.timeout_set = event["audit_conf"].get("timeout_set", aconf.timeout_set)
    aconf.verbose = event["audit_conf"].get("verbose", aconf.verbose)

    try:
        exit_code = audit(out, aconf)
        report = out.get_buffer()
    except Exception:
        exit_code = exitcodes.UNKNOWN_ERROR
        report = traceback.format_exc()

    match exit_code:
        case exitcodes.UNKNOWN_ERROR:
            http_code = 500
        case exitcodes.CONNECTION_ERROR:
            http_code = 400
        case _:
            http_code = 200

    return {
        "statusCode": http_code,
        "report": report,
    }
