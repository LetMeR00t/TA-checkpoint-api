# encoding = utf-8

import sys
import datetime
import json
import hashlib

# Import custom librairies
from pycheckpoint_api.management import Management
from pycheckpoint_api.management.exception import MandatoryFieldMissing, WrongType
import restfly

# Global
## Unique ID for the input execution
INPUT_UID = None
## Checkpoint instance name configured in the input
CKPT_INSTANCE = None
## Checkpoint domain of a given instance
DOMAIN = None

"""
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
"""
"""
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
"""


def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # instance = definition.parameters.get('instance', None)
    # account = definition.parameters.get('account', None)
    # items = definition.parameters.get('items', None)
    # details_level = definition.parameters.get('details_level', None)
    pass


def collect_events(helper, ew):
    """Implement your data collection logic here

    # The following examples get the arguments of this input.
    # Note, for single instance mod input, args will be returned as a dict.
    # For multi instance mod input, args will be returned as a single value.
    opt_instance = helper.get_arg('instance')
    opt_account = helper.get_arg('account')
    opt_items = helper.get_arg('items')
    opt_details_level = helper.get_arg('details_level')
    # In single instance mode, to get arguments of a particular input, use
    opt_instance = helper.get_arg('instance', stanza_name)
    opt_account = helper.get_arg('account', stanza_name)
    opt_items = helper.get_arg('items', stanza_name)
    opt_details_level = helper.get_arg('details_level', stanza_name)

    # get input type
    helper.get_input_type()

    # The following examples get input stanzas.
    # get all detailed input stanzas
    helper.get_input_stanza()
    # get specific input stanza with stanza name
    helper.get_input_stanza(stanza_name)
    # get all stanza names
    helper.get_input_stanza_names()

    # The following examples get options from setup page configuration.
    # get the loglevel from the setup page
    loglevel = helper.get_log_level()
    # get proxy setting configuration
    proxy_settings = helper.get_proxy()
    # get account credentials as dictionary
    account = helper.get_user_credential_by_username("username")
    account = helper.get_user_credential_by_id("account id")
    # get global variable configuration
    global_instance_1_hostname = helper.get_global_setting("instance_1_hostname")
    global_instance_1_port = helper.get_global_setting("instance_1_port")
    global_instance_1_api_version = helper.get_global_setting("instance_1_api_version")
    global_instance_1_domains = helper.get_global_setting("instance_1_domains")
    global_instance_1_ssl_verify = helper.get_global_setting("instance_1_ssl_verify")
    global_instance_2_hostname = helper.get_global_setting("instance_2_hostname")
    global_instance_2_port = helper.get_global_setting("instance_2_port")
    global_instance_2_api_version = helper.get_global_setting("instance_2_api_version")
    global_instance_2_domains = helper.get_global_setting("instance_2_domains")
    global_instance_2_ssl_verify = helper.get_global_setting("instance_2_ssl_verify")
    global_instance_3_hostname = helper.get_global_setting("instance_3_hostname")
    global_instance_3_port = helper.get_global_setting("instance_3_port")
    global_instance_3_api_version = helper.get_global_setting("instance_3_api_version")
    global_instance_3_domains = helper.get_global_setting("instance_3_domains")
    global_instance_3_ssl_verify = helper.get_global_setting("instance_3_ssl_verify")

    # The following examples show usage of logging related helper functions.
    # write to the log for this modular input using configured global log level or INFO as default
    helper.log("log message")
    # write to the log using specified log level
    helper.log_debug("log message")
    helper.log_info("log message")
    helper.log_warning("log message")
    helper.log_error("log message")
    helper.log_critical("log message")
    # set the log level for this modular input
    # (log_level can be "debug", "info", "warning", "error" or "critical", case insensitive)
    helper.set_log_level(log_level)

    # The following examples send rest requests to some endpoint.
    response = helper.send_http_request(url, method, parameters=None, payload=None,
                                        headers=None, cookies=None, verify=True, cert=None,
                                        timeout=None, use_proxy=True)
    # get the response headers
    r_headers = response.headers
    # get the response body as text
    r_text = response.text
    # get response body as json. If the body text is not a json string, raise a ValueError
    r_json = response.json()
    # get response cookies
    r_cookies = response.cookies
    # get redirect history
    historical_responses = response.history
    # get response status code
    r_status = response.status_code
    # check the response status, if the status is not sucessful, raise requests.HTTPError
    response.raise_for_status()

    # The following examples show usage of check pointing related helper functions.
    # save checkpoint
    helper.save_check_point(key, state)
    # delete checkpoint
    helper.delete_check_point(key)
    # get checkpoint
    state = helper.get_check_point(key)

    # To create a splunk event
    helper.new_event(data, time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
    """

    """
    # The following example writes a random number as an event. (Multi Instance Mode)
    # Use this code template by default.
    import random
    data = str(random.randint(0,100))
    event = helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=data)
    ew.write_event(event)
    """

    """
    # The following example writes a random number as an event for each input config. (Single Instance Mode)
    # For advanced users, if you want to create single instance mod input, please use this code template.
    # Also, you need to uncomment use_single_instance_mode() above.
    import random
    input_type = helper.get_input_type()
    for stanza_name in helper.get_input_stanza_names():
        data = str(random.randint(0,100))
        event = helper.new_event(source=input_type, index=helper.get_output_index(stanza_name), sourcetype=helper.get_sourcetype(stanza_name), data=data)
        ew.write_event(event)
    """
    helper.log_info(
        "[CKPT-I-START-COLLECT] Start to recover configuration events from Checkpoint Management API"
    )

    # Reference global variables
    global INPUT_UID
    global CKPT_INSTANCE
    global DOMAIN

    # Calculate a unique ID for the given input event recovery
    INPUT_UID = hashlib.sha256(str(datetime.datetime.now()).encode()).hexdigest()[:8]

    # Set the Checkpoint instance name
    CKPT_INSTANCE = list(helper.get_input_stanza().keys())[0]

    # Get information about the Splunk input
    opt_instance = helper.get_arg("instance")
    opt_items = helper.get_arg("items")
    opt_enable_membership_resolution = int(helper.get_arg("enable_membership_resolution"))
    opt_limit = int(helper.get_arg("limit"))
    opt_details_level = helper.get_arg("details_level")

    # Get credentials for Checkpoint API
    account = helper.get_arg("account")

    # Get information relative to the instance to use
    hostname = helper.get_global_setting("instance_" + str(opt_instance) + "_hostname")
    if hostname is None or hostname == "":
        helper.log_error(
            "[CKPT-E-HOSTNAME_NULL] No hostname was provided for instance nÃ‚Â°"
            + str(opt_instance)
            + ", check your configuration"
        )
        sys.exit(1)

    port = helper.get_global_setting("instance_" + str(opt_instance) + "_port")
    if port is None or port == "":
        helper.log_error(
            "[CKPT-E-PORT_NULL] No port was provided for instance nÃ‚Â°"
            + str(opt_instance)
            + ", check your configuration"
        )
        sys.exit(1)

    api_version = helper.get_global_setting(
        "instance_" + str(opt_instance) + "_api_version"
    )
    if api_version is None or api_version == "":
        helper.log_error(
            "[CKPT-E-API_VERSION_NULL] No API Version was provided for instance nÃ‚Â°"
            + str(opt_instance)
            + ", check your configuration"
        )
        sys.exit(1)

    # Get all the domains for the given instance
    domains = helper.get_global_setting("instance_" + str(opt_instance) + "_domains")
    if domains is not None:
        domains = domains.replace(" ", "").split(",")
    else:
        domains = [""]

    # Get all whitelisted policies
    whitelisted_policies = helper.get_global_setting(
        "instance_" + str(opt_instance) + "_whitelist_policies"
    )
    if whitelisted_policies is None or whitelisted_policies == "":
        # If no whitelist is provided, keep it as none
        whitelisted_policies = None
    else:
        whitelisted_policies = whitelisted_policies.replace(" ", "").split(",")

    # Check if we need to verify the certificate or not
    ssl_verify = (
        True
        if helper.get_global_setting("instance_" + str(opt_instance) + "_ssl_verify")
        == 1
        else False
    )

    # Global mapping between each item and the corresponding function to use
    ITEMS_MAP = {
        "host": {
            "key": "network_objects",
            "func": "show_hosts",
            "has_membership": True,
        },
        "network": {
            "key": "network_objects",
            "func": "show_networks",
            "has_membership": True,
        },
        "wildcard": {
            "key": "network_objects",
            "func": "show_wildcards",
            "has_membership": False,
        },
        "group": {
            "key": "network_objects",
            "func": "show_groups",
            "has_membership": True,
        },
        "gsn-handover-group": {
            "key": "network_objects",
            "func": "show_gsn_handover_groups",
            "has_membership": True,
        },
        "address-range": {
            "key": "network_objects",
            "func": "show_address_ranges",
            "has_membership": True,
        },
        "multicast-address-range": {
            "key": "network_objects",
            "func": "show_multicast_address_ranges",
            "has_membership": True,
        },
        "group-with-exclusion": {
            "key": "network_objects",
            "func": "show_groups_with_exclusion",
            "has_membership": False,
        },
        "simple-gateway": {
            "key": "network_objects",
            "func": "show_simple_gateways",
            "has_membership": True,
        },
        "simple-cluster": {
            "key": "network_objects",
            "func": "show_simple_clusters",
            "has_membership": True,
        },
        "checkpoint-host": {
            "key": "network_objects",
            "func": "show_checkpoint_hosts",
            "has_membership": True,
        },
        "security-zone": {
            "key": "network_objects",
            "func": "show_security_zones",
            "has_membership": True,
        },
        "time": {
            "key": "network_objects",
            "func": "show_times",
            "has_membership": False,
        },
        "time-group": {
            "key": "network_objects",
            "func": "show_time_groups",
            "has_membership": False,
        },
        "dynamic-object": {
            "key": "network_objects",
            "func": "show_dynamic_objects",
            "has_membership": True,
        },
        "tag": {"key": "network_objects", "func": "show_tags", "has_membership": False},
        "dns-domain": {
            "key": "network_objects",
            "func": "show_dns_domains",
            "has_membership": True,
        },
        "opsec-application": {
            "key": "network_objects",
            "func": "show_opsec_applications",
            "has_membership": True,
        },
        "lsv-profile": {
            "key": "network_objects",
            "func": "show_lsv_profiles",
            "has_membership": False,
        },
        "tacacs-server": {
            "key": "network_objects",
            "func": "show_tacacs_servers",
            "has_membership": False,
        },
        "tacacs-group": {
            "key": "network_objects",
            "func": "show_tacacs_groups",
            "has_membership": False,
        },
        "access-point-name": {
            "key": "network_objects",
            "func": "show_access_point_names",
            "has_membership": True,
        },
        "lsm-gateway": {
            "key": "network_objects",
            "func": "show_lsm_gateways",
            "has_membership": True,
        },
        "lsm-cluster": {
            "key": "network_objects",
            "func": "show_lsm_clusters",
            "has_membership": True,
        },
        "service-tcp": {
            "key": "service_applications",
            "func": "show_services_tcp",
            "has_membership": True,
        },
        "service-udp": {
            "key": "service_applications",
            "func": "show_services_udp",
            "has_membership": True,
        },
        "service-icmp": {
            "key": "service_applications",
            "func": "show_services_icmp",
            "has_membership": True,
        },
        "service-icmp6": {
            "key": "service_applications",
            "func": "show_services_icmp6",
            "has_membership": True,
        },
        "service-sctp": {
            "key": "service_applications",
            "func": "show_services_sctp",
            "has_membership": True,
        },
        "service-other": {
            "key": "service_applications",
            "func": "show_services_other",
            "has_membership": True,
        },
        "service-group": {
            "key": "service_applications",
            "func": "show_service_groups",
            "has_membership": True,
        },
        "application-site": {
            "key": "service_applications",
            "func": "show_application_sites",
            "has_membership": True,
        },
        "application-site-category": {
            "key": "service_applications",
            "func": "show_application_site_categories",
            "has_membership": False,
        },
        "application-site-group": {
            "key": "service_applications",
            "func": "show_application_site_groups",
            "has_membership": False,
        },
        "service-dce-rpc": {
            "key": "service_applications",
            "func": "show_services_dce_rpc",
            "has_membership": True,
        },
        "service-rpc": {
            "key": "service_applications",
            "func": "show_services_rpc",
            "has_membership": True,
        },
        "service-gtp": {
            "key": "service_applications",
            "func": "show_services_gtp",
            "has_membership": True,
        },
        "service-citrix-tcp": {
            "key": "service_applications",
            "func": "show_services_citrix_tcp",
            "has_membership": True,
        },
        "service-compound-tcp": {
            "key": "service_applications",
            "func": "show_services_compound_tcp",
            "has_membership": True,
        },
        "access-layer": {
            "key": "access_control_nat",
            "func": "show_access_layers",
            "has_membership": False,
        },
        "generic-objects": {
            "key": "misc",
            "func": "get_rulebaseactions",
            "has_membership": False,
        },
        "package": {"key": "policy", "func": "show_packages", "has_membership": False},
    }

    # Iterate over all the domains
    for domain in domains:
        DOMAIN = domain
        
        helper.log_info(
                '[CKPT-I-MANAGEMENT_DOMAIN] Start to process the domain named "'
                + domain
                + '" ("'
                + CKPT_INSTANCE
                + '")'
            )
            
        with Management(
            hostname=hostname,
            port=int(port),
            user=account["username"],
            password=account["password"],
            version=api_version,
            domain=domain,
            ssl_verify=ssl_verify,
        ) as firewall:

            helper.log_debug(
                "[CKPT-D-MANAGEMENT_OBJECT] Checkpoint Manager connection object is created successfully"
            )
            try:
                # Get items (simple methods)
                for item in opt_items:
                    # Check that the selected item is well supported by this script
                    if item in ITEMS_MAP:
                        # Get the item type (where the item is the Checkpoint type)
                        key = ITEMS_MAP[item]["key"]
                        # Get the associated function relative to the item
                        function = ITEMS_MAP[item]["func"]
                        # Check whether it can have membership (to calculate groups)
                        has_membership = ITEMS_MAP[item]["has_membership"]

                        # Specific process for generic-objects (not referenced in the Checkpoint API officialy)
                        if item == "generic-objects":
                            # Execute the request to recover the data (no parameter)
                            all_data = getattr(
                                getattr(getattr(firewall, key), item.replace("-", "_")),
                                function,
                            )()
                        else:
                            # Execute the request to recover the data (select all objets and with the required details levels)
                            final_params = {
                                "show_all": True,
                                "details_level": opt_details_level,
                                "limit": opt_limit,
                            }
                            if opt_enable_membership_resolution == 1 and has_membership:
                                final_params["show_membership"] = True
                            all_data = getattr(
                                getattr(getattr(firewall, key), item.replace("-", "_")),
                                function,
                            )(**final_params)

                        # Depending on the server response, we have to select the right key
                        if (
                            key in ["network_objects", "service_applications"]
                            or item == "generic-objects"
                        ):
                            all_data = all_data.objects
                        elif item == "access-layer":
                            all_data = all_data.access_layers
                        elif item == "package":
                            all_packages = all_data.packages
                            all_data = []
                            for p in all_data:
                                if (
                                    whitelisted_policies is None
                                    or p.name in whitelisted_policies
                                ):
                                    all_data += [p]

                        # Write those JSON events in Splunk
                        for data in all_data:
                            write_to_splunk(helper, ew, key + ":" + item, data)
                        log(helper, item, all_data)

                # Specific process for all access-rule
                item = "access-rule"
                if item in opt_items:
                    # Get access layers
                    access_layers = []
                    # Get all access layers
                    resp = firewall.access_control_nat.access_layer.show_access_layers(
                        limit=opt_limit
                    )
                    # Keep only domain type of access layers
                    if resp.total > 0:
                        als = resp.access_layers
                        for al in als:
                            if al.domain.domain_type == "domain":
                                access_layers.append(al)
                    # For each access layer, get the rules
                    for al in access_layers:
                        all_data = firewall.access_control_nat.access_rule.show_access_rulebase(
                            name=al.name, show_all=True, show_hits=True, limit=opt_limit
                        )
                        # Check if a section exists
                        section = ""
                        for rule in all_data.rulebase:
                            if rule.type == "access-section":
                                section = rule["name"]
                                # A section exists
                                for subrule in rule.rulebase:
                                    subrule["section"] = section
                                    write_to_splunk(
                                        helper,
                                        ew,
                                        "access_control_nat:"
                                        + item
                                        + ":"
                                        + al.name
                                        + ":"
                                        + rule.name
                                        + ":"
                                        + subrule.uid,
                                        subrule,
                                    )
                                log(
                                    helper,
                                    "access_control_nat:"
                                    + item
                                    + ":"
                                    + al.name
                                    + ":"
                                    + rule.name,
                                    subrule,
                                )
                            else:
                                # No section, it's a rule
                                rule["section"] = section
                                write_to_splunk(
                                    helper,
                                    ew,
                                    "access_control_nat:"
                                    + item
                                    + ":"
                                    + al.name
                                    + ":"
                                    + rule.uid,
                                    rule,
                                )
                                log(
                                    helper,
                                    "access_control_nat:"
                                    + item
                                    + ":"
                                    + al.name
                                    + ":"
                                    + rule.uid,
                                    all_data.rulebase,
                                )

                # Specific process for all nat-rule
                item = "nat-rule"
                if item in opt_items:
                    # Get packages
                    packages = firewall.policy.package.show_packages(
                        limit=opt_limit
                    ).packages
                    # For each package, get the rules
                    for p in packages:
                        if (
                            whitelisted_policies is None
                            or p.name in whitelisted_policies
                        ):
                            all_data = (
                                firewall.access_control_nat.nat_rule.show_nat_rulebase(
                                    package=p.name, show_all=True, limit=opt_limit
                                )
                            )
                            section = ""
                            # Check if a section exists
                            for rule in all_data.rulebase:
                                if rule.type == "nat-section":
                                    section = rule["name"]
                                    # A section exists
                                    for subrule in rule.rulebase:
                                        subrule["section"] = section
                                        write_to_splunk(
                                            helper,
                                            ew,
                                            "access_control_nat:"
                                            + item
                                            + ":"
                                            + p.name
                                            + ":"
                                            + rule.name
                                            + ":"
                                            + subrule.uid,
                                            subrule,
                                        )
                                    log(
                                        helper,
                                        "access_control_nat:"
                                        + item
                                        + ":"
                                        + p.name
                                        + ":"
                                        + rule.name,
                                        subrule,
                                    )
                                else:
                                    # No section, it's a rule
                                    rule["section"] = section
                                    write_to_splunk(
                                        helper,
                                        ew,
                                        "access_control_nat:"
                                        + item
                                        + ":"
                                        + p.name
                                        + ":"
                                        + rule.uid,
                                        rule,
                                    )
                                    log(
                                        helper,
                                        "access_control_nat:"
                                        + item
                                        + ":"
                                        + p.name
                                        + ":"
                                        + rule.uid,
                                        all_data.rulebase,
                                    )

            except (MandatoryFieldMissing, WrongType) as e:
                helper.log_error(
                    "[CKPT-E-LIBRARY_ERROR] 🔴 Your request raised an issue: " + str(e)
                )
                sys.exit(14)
            except restfly.errors.BadRequestError as e:
                helper.log_error(
                    "[CKPT-E-BAD_REQUEST] 🔴 Your request is not correct and was rejected by Checkpoint: "
                    + str(e.msg.replace('"', "'"))
                )
                sys.exit(15)
            except restfly.errors.ForbiddenError as e:
                helper.log_error(
                    "[CKPT-E-FORBIDDEN_REQUEST] 🔴 Your request is forbidden and was rejected by Checkpoint: "
                    + str(e.msg.replace('"', "'"))
                )
                sys.exit(16)

    helper.log_info(
        "[CKPT-I-END-COLLECT] 🟢 Events from Checkpoint API ("
        + str(opt_items)
        + ") are recovered"
    )


# This function is writing events in Splunk
def write_to_splunk(helper, ew, item, data):
    event = helper.new_event(
        source="CKPT:" + CKPT_INSTANCE + ":" + INPUT_UID + ":" + DOMAIN + ":" + item,
        index=helper.get_output_index(),
        sourcetype=helper.get_sourcetype(),
        data=json.dumps(data),
    )
    ew.write_event(event)


# This function is logging information in the search.log
def log(helper, item, all_data):
    if len(all_data) > 0 and all_data != []:
        helper.log_debug(
            "[CKPT-D-EVENTS_WRITTEN] Events are written for "
            + item
            + " to the index "
            + helper.get_output_index()
            + ": "
            + str(all_data)
        )
    else:
        helper.log_debug("[CKPT-D-NO_EVENT_FOUND] No event found for " + item)
